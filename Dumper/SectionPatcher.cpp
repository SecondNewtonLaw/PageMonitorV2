//
// Created by Dottik on 16/2/2025.
//

#include "SectionPatcher.hpp"

#include <functional>

#include "Logger.hpp"

namespace Dottik::Dumper {
    Function::Function(const std::uintptr_t functionStart, const std::uintptr_t functionEnd) {
        this->lpFunctionStart = functionStart;
        this->lpFunctionEnd = functionEnd;
    }

    SectionPatcher::SectionPatcher(const csh &csh, const PE::SectionInformation &sectionData) {
        this->m_csHandle = csh;
        this->m_sectionInformation = sectionData;
    }

    std::vector<Function> SectionPatcher::FindFunctions() {
        std::unordered_map<std::uintptr_t, Function> functions{};
        functions.reserve(2048); // Approximately these more of these functions we will find on real apps.

        auto insn = cs_malloc(this->m_csHandle);

        do {
            auto pageSize = static_cast<std::size_t>(this->m_sectionInformation.dwSectionSize);
            auto startChunk = static_cast<const std::uint8_t *>(this->m_sectionInformation.pSectionBegin);
            auto currentAddress = reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.pSectionBegin);

            DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                      "Building function list (by call operands)...");

            while (cs_disasm_iter(this->m_csHandle, &startChunk, &pageSize,
                                  &currentAddress, insn)) {
                int counter = 0;
                auto isCallInstruction = false;
                while (counter <= insn->detail->groups_count) {
                    if (insn->detail->groups[counter++] == CS_GRP_CALL) {
                        isCallInstruction = true;
                        break;
                    }
                }

                if (!isCallInstruction)
                    continue;

                auto functionStart = insn->detail->x86.operands->mem.disp +
                                     insn->address +
                                     insn->size;

                if (functionStart < reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.pSectionBegin) ||
                    functionStart > reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.pSectionEnd)) {
                    //DottikLog(Dottik::LogType::Debug, Dottik::DumpingEngine,
                    //          std::format(
                    //              "Call to the outside of the target segment? Is this a call product of a hook or something?"
                    //          ));
                    continue;
                }

                functions[functionStart] = Function{
                    functionStart,
                    static_cast<unsigned long long>(-1)
                };
            }
        } while (false);

        DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                  std::format("Finding function endings for {} functions...", functions.size()));

        std::vector<Function> functionsVector{};
        functionsVector.reserve(functions.size());

        for (auto begin = functions.begin(); begin != functions.end(); ++begin) {
            auto functionSize = static_cast<std::size_t>(0x1000);
            auto startChunk = static_cast<const std::uint8_t *>(reinterpret_cast<void *>(begin->second.
                lpFunctionStart));
            auto currentAddress = begin->second.lpFunctionStart;

            /*
             *  Due to the fact functions may be at the *end* of the section, if we grab an entire page we may crash or cause problems.
             *  To prevent this we must calculate the actual function size bounded by the section's end address.
             */

            if ((currentAddress + functionSize) > reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                    pSectionEnd)) {
                functionSize = reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.pSectionEnd) -
                               currentAddress; // Bound to pSectionEnd.
            }

            bool hasThereBeenAnInstructionBefore = false;
            uint64_t eflagsOfPreviousInstruction = {};
            uint8_t previousInstructionGroups[8] = {};

            while (cs_disasm_iter(this->m_csHandle, &startChunk, &functionSize,
                                  &currentAddress, insn)) {
                int counter = 0;
                auto isInterrupt = false;
                auto isReturn = false;
                while (insn->detail->groups_count != 0 && counter <= insn->detail->groups_count) {
                    if (insn->detail->groups[counter++] == CS_GRP_INT) {
                        isInterrupt = true;
                    }

                    if (insn->detail->groups[counter++] == CS_GRP_RET) {
                        isReturn = true;
                    }
                }

                if (isInterrupt) {
                    {
                        int counterAgain = 0;
                        auto isCallInstruction = false;
                        while (counterAgain <= sizeof(previousInstructionGroups)) {
                            if (previousInstructionGroups[counterAgain++] == CS_GRP_CALL) {
                                isCallInstruction = true;
                                break;
                            }
                        }

                        if (isCallInstruction) {
                            // The previous instruction was a CALL instruction.
                            // However, the current instruction is an interrupt instruction.
                            // This means that the call is a NO_RETURN type call, and thus we declare the function's end right in here.
                            begin->second.lpFunctionEnd = currentAddress - insn->size;
                            break;
                        }
                    }

                    if (eflagsOfPreviousInstruction) {
                        // The previous instruction modified an EFLAG. This means that the following
                        // interrupts are to be completely ignored.

                        std::uintptr_t overwriteAddress = insn->address;
                        int overwriteSize = insn->size;
                        while (cs_disasm_iter(this->m_csHandle, &startChunk, &functionSize,
                                              &currentAddress, insn)) {
                            int counter = 0;
                            auto isInterrupt = false;
                            while (counter <= insn->detail->groups_count) {
                                if (insn->detail->groups[counter++] == CS_GRP_INT) {
                                    isInterrupt = true;
                                    break;
                                }
                            }

                            if (!isInterrupt) break;
                            overwriteSize += insn->size;
                        }

                        memset(reinterpret_cast<void *>(overwriteAddress), 0x90, overwriteSize);
                    } else {
                        if (hasThereBeenAnInstructionBefore) {
                            // Function ends here.
                            begin->second.lpFunctionEnd = currentAddress - insn->size;
                            break;
                        }

                        std::uintptr_t overwriteAddress = insn->address;
                        int overwriteSize = insn->size;
                        while (cs_disasm_iter(this->m_csHandle, &startChunk, &functionSize,
                                              &currentAddress, insn)) {
                            int counter = 0;
                            auto isInterrupt = false;
                            while (counter <= insn->detail->groups_count) {
                                if (insn->detail->groups[counter++] == CS_GRP_INT) {
                                    isInterrupt = true;
                                    break;
                                }
                            }

                            if (!isInterrupt) break;
                            overwriteSize += insn->size;
                        }

                        memset(reinterpret_cast<void *>(overwriteAddress), 0x90, overwriteSize);
                    }
                }

                if (isReturn) {
                    // The function ends here.
                    begin->second.lpFunctionEnd = currentAddress - insn->size;
                    break;
                }

                ASSUME(sizeof(insn->detail->groups) == sizeof(previousInstructionGroups),
                       "The size of the groups is not equal to the previous instruction groups C array size. How.");
                memcpy(previousInstructionGroups, insn->detail->groups, sizeof(insn->detail->groups));
                eflagsOfPreviousInstruction = insn->detail->x86.eflags;
                hasThereBeenAnInstructionBefore = true;
            }

            if (begin->second.lpFunctionEnd == -1) {
                continue;
            }

            functionsVector.emplace_back(begin->second.lpFunctionStart, begin->second.lpFunctionEnd);
            // ASSUME(begin->second.lpFunctionEnd != -1, "Failed to find function ending.");
        }

        DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine, "Determined function endings.");

        cs_free(insn, 1);

        return functionsVector;
    }

    void SectionPatcher::PatchFunction(const Function &function) {
        const auto insn = cs_malloc(this->m_csHandle);

        do {
            auto pageSize = static_cast<std::size_t>(function.lpFunctionEnd - function.lpFunctionStart);
            auto startChunk = reinterpret_cast<const std::uint8_t *>(function.lpFunctionStart);
            auto currentAddress = static_cast<std::uintptr_t>(function.lpFunctionStart);

            while (cs_disasm_iter(this->m_csHandle, &startChunk, &pageSize,
                                  &currentAddress, insn)) {
                int counter = 0;
                while (counter <= insn->detail->groups_count) {
                    if (insn->detail->groups[counter++] == CS_GRP_INT) {
                        memset(reinterpret_cast<void *>(const_cast<std::uint8_t *>(startChunk)), 0x90, insn->size);
                        break;
                    }
                }
            }
        } while (false);

        cs_free(insn, 1);
    }
}
