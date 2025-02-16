//
// Created by Dottik on 10/8/2024.
//
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace Dottik {
    enum LogType {
        Information, Warning, Error, Debug
    };

    class Logger final {
        /// @brief Private, Static shared pointer into the instance.
        static std::shared_ptr<Logger> pInstance;

        /// @brief Disables buffering.
        bool m_bInstantFlush;
        /// @brief Defines whether the Logger instance is initialized or not.
        bool m_bInitialized;
        /// @brief The size of the buffer.
        std::uint32_t m_dwBufferSize;
        /// @brief The buffer used to store messages.
        std::string m_szMessageBuffer;
        std::string m_szHistoryLog;

        /// @brief Flushes the buffer into the standard output.
        void Flush(Dottik::LogType messageType);

        /// @brief Flushes the buffer only if the buffer is full.
        void FlushIfFull(Dottik::LogType messageType);

    public:
        /// @brief Obtains the Singleton for the Logger instance.
        /// @return Returns a shared pointer to the global Logger singleton instance.
        static std::shared_ptr<Logger> GetSingleton();

        /// @brief Initializes the Logger instance by opening the standard pipes, setting up the buffer and its size.
        /// @param bInstantFlush Whether the logger should keep no buffer, and let the underlying implementation for
        /// stdio and files handle it.
        void Initialize(bool bInstantFlush);

        void PrintDebug(std::string_view sectionName, std::string_view msg, std::string_view line);

        /// @brief Emits an Information with the given section name into the Logger's buffer.
        /// @param sectionName The name of the section that the code is running at
        /// @param msg The content to write into the buffer, as an information.
        /// @param line
        void PrintInformation(std::string_view sectionName, std::string_view msg, std::string_view line);

        /// @brief Emits a Warning with the given section name into the Logger's buffer.
        /// @param sectionName The name of the section that the code is running at
        /// @param msg The content to write into the buffer, as a warning.
        /// @param line
        void PrintWarning(std::string_view sectionName, std::string_view msg, std::string_view line);

        /// @brief Emits an error with the given section name into the Logger's buffer.
        /// @param sectionName The name of the section that the code is running at
        /// @param msg The content to write into the buffer, as an error.
        /// @param line
        void PrintError(std::string_view sectionName, std::string_view msg, std::string_view line);

        std::string &GetHistoryLog();

        bool IsNewLogAvailable();

        void MarkRead();
    };

    /// @brief Defines a section for use in the logger
#define DefineSectionName(varName, sectionName) constexpr auto varName = sectionName
    DefineSectionName(Rendering, "Dottik::D3D11");
    DefineSectionName(MainThread, "Dottik::MainThread");
    DefineSectionName(WinAPI, "Dottik::WinAPI");
    DefineSectionName(DumpingEngine, "Dottik::DumpingEngine");
#undef DefineSectionName
}; // namespace RbxStu

#define DottikLog(logType, sectionName, logMessage)                                                                    \
    {                                                                                                                  \
        const auto logger = Dottik::Logger::GetSingleton();                                                            \
        switch (logType) {                                                                                             \
            case Dottik::LogType::Information:                                                                         \
                logger->PrintInformation(sectionName, logMessage, __FUNCTION__);                                       \
                break;                                                                                                 \
            case Dottik::LogType::Warning:                                                                             \
                logger->PrintWarning(sectionName, logMessage, __FUNCTION__);                                           \
                break;                                                                                                 \
            case Dottik::LogType::Error:                                                                               \
                logger->PrintError(sectionName, logMessage, __FUNCTION__);                                             \
                break;                                                                                                 \
            case Dottik::LogType::Debug:                                                                               \
                logger->PrintDebug(sectionName, logMessage, __FUNCTION__);                                             \
                break;                                                                                                 \
        }                                                                                                              \
    }
