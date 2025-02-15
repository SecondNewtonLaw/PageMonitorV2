cmake_minimum_required(VERSION 3.29)
project(PageMonitorV2)

enable_language(CXX C ASM_MASM)

set(CMAKE_CXX_STANDARD 23)
file(GLOB ASSEMBLY_FILES ${PROJECT_SOURCE_DIR}/Assembly/*.x64.asm)
string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)

if (build_type STREQUAL release)
    message("Build is in Release Mode; Adding custom Compiler options and Linker options.")
    add_compile_options(
            /MT
            /GA
            /EHa
            /bigobj
            /O2
            /Gr
            /GS
            /GR-
            /GF
            /GL
            /cgthreads8
            /arch:AVX2
    )

    add_link_options(
            /LTCG
            /INCREMENTAL
            /DEBUG
            /DYNAMICBASE
            /HIGHENTROPYVA
            /GUARD:CF
            /VERBOSE
    )
endif ()

add_executable(${PROJECT_NAME}
        main.cpp

        Assembly/functions.h
        ${ASSEMBLY_FILES}
        AssemblyObfuscations.hpp

        Logger.cpp
        Logger.hpp

        Graphics/Render/Dx11.cpp
        Graphics/Render/Dx11.hpp
        Graphics/Render/RenderManager.cpp
        Graphics/Render/RenderManager.hpp

        Graphics/ImmediateGui/Keycodes.hpp
        Graphics/ImmediateGui/PagedWindow.cpp
        Graphics/ImmediateGui/PagedWindow.hpp

        Graphics/UserInterface/UserInterface.cpp
        Graphics/UserInterface/UserInterface.hpp
        Graphics/UserInterface/Pages/CreditsPage.cpp
        Graphics/UserInterface/Pages/CreditsPage.hpp
        Graphics/UserInterface/Pages/SettingsPage.cpp
        Graphics/UserInterface/Pages/SettingsPage.hpp

        Graphics/Color4.hpp
        Graphics/Renderable.cpp
        Graphics/Renderable.hpp
        Graphics/RenderableStub.hpp
        Graphics/Render/RenderBackend.hpp
        Exceptions/RenderInitializationError.hpp
        Dumper/Dumper.cpp
        Dumper/Dumper.hpp
        Dumper/Readers/RemoteReader.hpp
        Dumper/Readers/WinApi.cpp
        Dumper/Readers/WinApi.hpp
        Dumper/ProcessImage.hpp
        Dumper/ImageDumper.cpp
        Dumper/ImageDumper.hpp
)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/Dependencies/include)

add_subdirectory(${PROJECT_SOURCE_DIR}/Dependencies/Capstone)
add_subdirectory(${PROJECT_SOURCE_DIR}/Dependencies/Imgui)
add_subdirectory(${PROJECT_SOURCE_DIR}/Dependencies/libassert)

target_link_libraries(${PROJECT_NAME}
        PUBLIC

        capstone::capstone

        Imgui

        libassert::assert
)