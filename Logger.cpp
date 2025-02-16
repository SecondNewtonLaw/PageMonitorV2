//
// Created by Dottik on 10/8/2024.
//

#include "Logger.hpp"

#include <Termcolor.hpp>
#include <format>
#include <iostream>
#include <mutex>
#include <shared_mutex>

std::shared_mutex mutex;
std::shared_ptr<Dottik::Logger> Dottik::Logger::pInstance;

std::shared_ptr<Dottik::Logger> Dottik::Logger::GetSingleton() {
    if (Dottik::Logger::pInstance == nullptr)
        Dottik::Logger::pInstance = std::make_shared<Dottik::Logger>();

    return Dottik::Logger::pInstance;
}

void Dottik::Logger::Flush(const Dottik::LogType messageType) {
    // TODO: Implement flushing to file.
    switch (messageType) {
        case Dottik::LogType::Error:
            std::cout << termcolor::bright_red << this->m_szMessageBuffer << termcolor::reset << std::endl;
            break;
        case Dottik::LogType::Warning:
            std::cout << termcolor::bright_yellow << this->m_szMessageBuffer << termcolor::reset << std::endl;
            break;
        case Dottik::LogType::Information:
            std::cout << termcolor::bright_blue << this->m_szMessageBuffer << termcolor::reset << std::endl;
            break;
        case Dottik::LogType::Debug:
            std::cout << termcolor::bright_white << this->m_szMessageBuffer << termcolor::reset << std::endl;
            break;
    }

    this->m_szHistoryLog += this->m_szMessageBuffer + "\r\n";
    this->m_szMessageBuffer.clear();
}

void Dottik::Logger::FlushIfFull(const Dottik::LogType messageType) {
    if (!this->m_bInitialized)
        throw std::exception(
            std::format("The logger instance @ {} is not initialized!", reinterpret_cast<uintptr_t>(this)).c_str());

    if (this->m_bInstantFlush || this->m_szMessageBuffer.length() >= this->m_dwBufferSize)
        this->Flush(messageType);
}

void Dottik::Logger::Initialize(const bool bInstantFlush) {
    if (this->m_bInitialized)
        return;

    printf(R"(
'########:::::'###:::::'######:::'########:::::'##::::'##::'#######::'##::: ##:'####:'########::'#######::'########::::::'##::::'##::'#######::
 ##.... ##:::'## ##:::'##... ##:: ##.....:::::: ###::'###:'##.... ##: ###:: ##:. ##::... ##..::'##.... ##: ##.... ##::::: ##:::: ##:'##.... ##:
 ##:::: ##::'##:. ##:: ##:::..::: ##::::::::::: ####'####: ##:::: ##: ####: ##:: ##::::: ##:::: ##:::: ##: ##:::: ##::::: ##:::: ##:..::::: ##:
 ########::'##:::. ##: ##::'####: ######::::::: ## ### ##: ##:::: ##: ## ## ##:: ##::::: ##:::: ##:::: ##: ########:::::: ##:::: ##::'#######::
 ##.....::: #########: ##::: ##:: ##...:::::::: ##. #: ##: ##:::: ##: ##. ####:: ##::::: ##:::: ##:::: ##: ##.. ##:::::::. ##:: ##::'##::::::::
 ##:::::::: ##.... ##: ##::: ##:: ##::::::::::: ##:.:: ##: ##:::: ##: ##:. ###:: ##::::: ##:::: ##:::: ##: ##::. ##:::::::. ## ##::: ##::::::::
 ##:::::::: ##:::: ##:. ######::: ########::::: ##:::: ##:. #######:: ##::. ##:'####:::: ##::::. #######:: ##:::. ##:::::::. ###:::: #########:
..:::::::::..:::::..:::......::::........::::::..:::::..:::.......:::..::::..::....:::::..::::::.......:::..:::::..:::::::::...:::::.........::
)");

    this->m_dwBufferSize = 0xffff;
    this->m_szMessageBuffer = std::string("");
    this->m_szMessageBuffer.reserve(this->m_dwBufferSize);
    this->m_bInstantFlush = bInstantFlush;
    this->m_bInitialized = true;
    std::atexit([] {
        auto logger = Dottik::Logger::GetSingleton();
        logger->Flush(Dottik::LogType::Information);
        logger->m_szMessageBuffer.clear();
        logger.reset();
    });
}

void Dottik::Logger::PrintDebug(std::string_view sectionName, std::string_view msg, std::string_view line) {
#if _DEBUG
    std::lock_guard lock{mutex};
    this->m_szMessageBuffer.append(std::format("[DEBUG/{} -> {}] {}", sectionName, line, msg));
    this->FlushIfFull(Dottik::LogType::Debug);
#endif
}

void Dottik::Logger::PrintInformation(std::string_view sectionName, std::string_view msg, std::string_view line) {
    std::lock_guard lock{mutex};
    this->m_szMessageBuffer.append(std::format("[INFO/{} -> {}] {}", sectionName, line, msg));
    this->FlushIfFull(Dottik::LogType::Information);
}

void Dottik::Logger::PrintWarning(std::string_view sectionName, std::string_view msg, std::string_view line) {
    std::lock_guard lock{mutex};
    this->m_szMessageBuffer.append(std::format("[WARN/{} -> {}] {}", sectionName, line, msg));
    this->FlushIfFull(Dottik::LogType::Warning);
}

void Dottik::Logger::PrintError(std::string_view sectionName, std::string_view msg, std::string_view line) {
    std::lock_guard lock{mutex};
    this->m_szMessageBuffer.append(std::format("[ERROR/{} -> {}] {}", sectionName, line, msg));
    this->FlushIfFull(Dottik::LogType::Error);
}

bool Dottik::Logger::IsNewLogAvailable() {
    std::lock_guard lock{mutex};
    return !this->m_szHistoryLog.empty();
}

void Dottik::Logger::MarkRead() {
    std::lock_guard lock{mutex};
    this->m_szHistoryLog.clear();
}

std::string &Dottik::Logger::GetHistoryLog() {
    std::lock_guard lock{mutex};
    return this->m_szHistoryLog;
}
