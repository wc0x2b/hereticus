//! Passes that rewrite a function into longer, equivalent code, as the
//! obfuscators of the game-hacking scene do, so a test can check that
//! `hereticus` still pairs each function with the one it came from.
//!
//! Three passes, from Obfuscator-LLVM:
//!
//! * `substitution` rewrites integer arithmetic. `a + b` becomes
//!   `a - (-b)`, and `a ^ b` becomes `(a | b) & ~(a & b)`. The x86 and
//!   ARM back ends fold most of these forms back when they select
//!   instructions, so this pass changes little machine code on its own.
//!   It stands as the simplest mutation a reader must not be fooled by.
//! * `flatten` flattens the control flow. It puts every basic block of a
//!   function under one `switch`, and a block sets a state variable and
//!   jumps back to the `switch` in place of branching to its successor. The
//!   back end cannot undo this, so the machine code of a flattened function
//!   shares few instructions with the plain one, yet does the same work.
//! * `bogus` adds bogus control flow. It guards the body of each block with
//!   a branch on an opaque predicate, `x * (x + 1)` is even, which holds for
//!   every `x` but which the compiler cannot fold, because `x` is a load
//!   from a mutable global. The branch that is never taken goes to a clone
//!   of the body, so the function grows a path that never runs.
//!
//! Each pass is deterministic, so a function and its edit mutate the same
//! way, and a diff of the two mutated binaries shows only the edit. The
//! passes run after the optimizer, through `registerOptimizerLastEPCallback`,
//! so the optimizer does not fold the longer forms back. The environment
//! variable `HERETICUS_OBFUSCATE`, a comma-separated list of pass names,
//! says which to run there; it defaults to `flatten`.

#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <cstdlib>
// Debian's LLVM 22 keeps `PassPlugin.h` under `llvm/Plugins`, where upstream
// keeps it under `llvm/Passes`.
#if __has_include("llvm/Passes/PassPlugin.h")
#include "llvm/Passes/PassPlugin.h"
#else
#include "llvm/Plugins/PassPlugin.h"
#endif

#include <vector>

using namespace llvm;

namespace {

// Replace `op` with an equivalent run of instructions, or return nullptr
// where the pass leaves it as it is. `builder` inserts before `op`.
Value *substitute(BinaryOperator *op, IRBuilder<> &builder) {
  Value *lhs = op->getOperand(0);
  Value *rhs = op->getOperand(1);
  switch (op->getOpcode()) {
  case Instruction::Add:
    return builder.CreateSub(lhs, builder.CreateNeg(rhs));
  case Instruction::Sub:
    return builder.CreateAdd(lhs, builder.CreateNeg(rhs));
  case Instruction::Xor:
    return builder.CreateAnd(builder.CreateOr(lhs, rhs),
                             builder.CreateNot(builder.CreateAnd(lhs, rhs)));
  default:
    return nullptr;
  }
}

bool substituteIn(Function &function) {
  SmallVector<BinaryOperator *, 16> targets;
  for (Instruction &instruction : instructions(function))
    if (auto *op = dyn_cast<BinaryOperator>(&instruction))
      if (op->getType()->isIntegerTy())
        targets.push_back(op);

  for (BinaryOperator *op : targets) {
    IRBuilder<> builder(op);
    if (Value *replacement = substitute(op, builder)) {
      op->replaceAllUsesWith(replacement);
      op->eraseFromParent();
    }
  }
  return !targets.empty();
}

// Move every value used outside its block, and every PHI, to a stack slot,
// so the control flow can move the blocks without breaking the SSA form.
void demoteAcrossBlocks(Function &function) {
  SmallVector<PHINode *, 16> phis;
  SmallVector<Instruction *, 16> escaping;
  for (BasicBlock &block : function) {
    for (Instruction &instruction : block) {
      if (isa<AllocaInst>(instruction))
        continue;
      if (auto *phi = dyn_cast<PHINode>(&instruction)) {
        phis.push_back(phi);
        continue;
      }
      bool crosses = llvm::any_of(instruction.users(), [&](User *user) {
        auto *used = dyn_cast<Instruction>(user);
        return used && (used->getParent() != &block || isa<PHINode>(used));
      });
      if (crosses)
        escaping.push_back(&instruction);
    }
  }
  for (PHINode *phi : phis)
    DemotePHIToStack(phi);
  for (Instruction *instruction : escaping)
    DemoteRegToStack(*instruction);
}

bool flatten(Function &function) {
  if (function.isDeclaration())
    return false;
  // A block that unwinds or jumps through a register is more than this
  // models, so a function with one is left as it is.
  for (BasicBlock &block : function) {
    Instruction *terminator = block.getTerminator();
    if (isa<InvokeInst>(terminator) || isa<IndirectBrInst>(terminator))
      return false;
  }

  std::vector<BasicBlock *> blocks;
  for (BasicBlock &block : function)
    blocks.push_back(&block);
  if (blocks.size() <= 1)
    return false;
  blocks.erase(blocks.begin());

  LLVMContext &context = function.getContext();
  IntegerType *i32 = Type::getInt32Ty(context);
  BasicBlock *entry = &function.getEntryBlock();

  // Where the entry block ends in a choice, split off the choice so the
  // dispatcher holds it, and the entry block only sets the first state.
  if (auto *branch = dyn_cast<BranchInst>(entry->getTerminator());
      branch && branch->isConditional()) {
    BasicBlock *split = entry->splitBasicBlock(std::prev(entry->end()), "entry.tail");
    blocks.insert(blocks.begin(), split);
  }
  entry->getTerminator()->eraseFromParent();

  IRBuilder<> entryBuilder(entry);
  AllocaInst *state = entryBuilder.CreateAlloca(i32, nullptr, "cff.state");
  entryBuilder.CreateStore(ConstantInt::get(i32, 0), state);

  BasicBlock *dispatch = BasicBlock::Create(context, "cff.dispatch", &function);
  BasicBlock *backedge = BasicBlock::Create(context, "cff.backedge", &function);
  BasicBlock *fallback = BasicBlock::Create(context, "cff.default", &function);
  entryBuilder.CreateBr(dispatch);

  IRBuilder<> dispatchBuilder(dispatch);
  LoadInst *current = dispatchBuilder.CreateLoad(i32, state, "cff.current");
  SwitchInst *selector =
      dispatchBuilder.CreateSwitch(current, fallback, blocks.size());
  IRBuilder<>(fallback).CreateBr(backedge);
  IRBuilder<>(backedge).CreateBr(dispatch);

  // Each block gets a number, counted from zero, so the entry block's
  // first state, zero, selects the block it used to flow into.
  for (unsigned number = 0; number < blocks.size(); ++number) {
    blocks[number]->moveBefore(backedge);
    selector->addCase(ConstantInt::get(i32, number), blocks[number]);
  }

  for (BasicBlock *block : blocks) {
    Instruction *terminator = block->getTerminator();
    unsigned successors = terminator->getNumSuccessors();
    IRBuilder<> builder(terminator);
    if (successors == 1) {
      ConstantInt *next = selector->findCaseDest(terminator->getSuccessor(0));
      if (!next)
        continue;
      builder.CreateStore(next, state);
      builder.CreateBr(backedge);
      terminator->eraseFromParent();
    } else if (successors == 2) {
      auto *branch = cast<BranchInst>(terminator);
      ConstantInt *onTrue = selector->findCaseDest(branch->getSuccessor(0));
      ConstantInt *onFalse = selector->findCaseDest(branch->getSuccessor(1));
      if (!onTrue || !onFalse)
        continue;
      Value *next = builder.CreateSelect(branch->getCondition(), onTrue, onFalse);
      builder.CreateStore(next, state);
      builder.CreateBr(backedge);
      terminator->eraseFromParent();
    }
    // A block that returns keeps its terminator and leaves the loop.
  }

  demoteAcrossBlocks(function);
  return true;
}

// A mutable global the compiler cannot read, so a predicate on it stays.
GlobalVariable *opaqueGlobal(Module &module) {
  IntegerType *i32 = Type::getInt32Ty(module.getContext());
  if (auto *existing = module.getGlobalVariable("cff.opaque"))
    return existing;
  return new GlobalVariable(module, i32, /*isConstant=*/false,
                            GlobalValue::InternalLinkage,
                            ConstantInt::get(i32, 0), "cff.opaque");
}

// A clone of `block` in `function`, with each value its own instructions
// define remapped to the clone.
BasicBlock *cloneBlock(BasicBlock *block, Function &function) {
  ValueToValueMapTy map;
  BasicBlock *clone = CloneBasicBlock(block, map, ".bogus", &function);
  for (Instruction &instruction : *clone)
    RemapInstruction(&instruction, map,
                     RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
  return clone;
}

// Guard the body of `block` with an opaque predicate, and send the branch
// that never runs to a clone of the body.
void addBogusFlow(BasicBlock *block, GlobalVariable *global) {
  Function &function = *block->getParent();
  IntegerType *i32 = cast<IntegerType>(global->getValueType());

  BasicBlock *body =
      block->splitBasicBlock(block->getFirstInsertionPt(), block->getName() + ".body");
  BasicBlock *bogus = cloneBlock(body, function);
  bogus->getTerminator()->eraseFromParent();
  IRBuilder<>(bogus).CreateBr(body);

  // `block` now ends in the split's unconditional branch; replace it with
  // the opaque choice. `x * (x + 1)` is even, so the low bit is zero and
  // the real body always runs.
  block->getTerminator()->eraseFromParent();
  IRBuilder<> builder(block);
  Value *x = builder.CreateLoad(i32, global, "cff.x");
  Value *product = builder.CreateMul(x, builder.CreateAdd(x, ConstantInt::get(i32, 1)));
  Value *low = builder.CreateAnd(product, ConstantInt::get(i32, 1));
  Value *even = builder.CreateICmpEQ(low, ConstantInt::get(i32, 0));
  builder.CreateCondBr(even, body, bogus);
}

bool bogusFlow(Function &function) {
  if (function.isDeclaration())
    return false;
  SmallVector<BasicBlock *, 16> blocks;
  for (BasicBlock &block : function) {
    if (block.isEHPad() || block.isLandingPad())
      return false;
    Instruction *terminator = block.getTerminator();
    if (isa<InvokeInst>(terminator) || isa<IndirectBrInst>(terminator))
      return false;
    // A block with only a few instructions in its body gives the clone
    // nothing worth hiding, so it is left as it is.
    if (block.size() >= 3)
      blocks.push_back(&block);
  }
  if (blocks.empty())
    return false;

  GlobalVariable *global = opaqueGlobal(*function.getParent());
  for (BasicBlock *block : blocks)
    addBogusFlow(block, global);
  demoteAcrossBlocks(function);
  return true;
}

struct Substitution : PassInfoMixin<Substitution> {
  PreservedAnalyses run(Function &function, FunctionAnalysisManager &) {
    bool changed = substituteIn(function);
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

struct Flatten : PassInfoMixin<Flatten> {
  PreservedAnalyses run(Function &function, FunctionAnalysisManager &) {
    bool changed = flatten(function);
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

struct Bogus : PassInfoMixin<Bogus> {
  PreservedAnalyses run(Function &function, FunctionAnalysisManager &) {
    bool changed = bogusFlow(function);
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

// Add the passes that `HERETICUS_OBFUSCATE` names to `manager`, or
// flattening where the variable is unset. Each name is run as it reads.
void addSelected(FunctionPassManager &manager) {
  const char *selection = std::getenv("HERETICUS_OBFUSCATE");
  if (!selection || !*selection) {
    manager.addPass(Flatten());
    return;
  }
  for (StringRef rest = selection; !rest.empty();) {
    StringRef name;
    std::tie(name, rest) = rest.split(',');
    name = name.trim();
    if (name == "flatten")
      manager.addPass(Flatten());
    else if (name == "bogus")
      manager.addPass(Bogus());
    else if (name == "substitution")
      manager.addPass(Substitution());
  }
}

} // namespace

// Register both passes by name, and run flattening after the optimizer so
// `-fpass-plugin` applies it to each function.
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "HereticusObfuscate", "0.1",
          [](PassBuilder &builder) {
            builder.registerPipelineParsingCallback(
                [](StringRef name, FunctionPassManager &manager,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (name == "substitution") {
                    manager.addPass(Substitution());
                    return true;
                  }
                  if (name == "flatten") {
                    manager.addPass(Flatten());
                    return true;
                  }
                  if (name == "bogus") {
                    manager.addPass(Bogus());
                    return true;
                  }
                  return false;
                });
            builder.registerOptimizerLastEPCallback(
                [](ModulePassManager &manager, OptimizationLevel,
                   ThinOrFullLTOPhase) {
                  FunctionPassManager functions;
                  addSelected(functions);
                  manager.addPass(createModuleToFunctionPassAdaptor(std::move(functions)));
                });
          }};
}
