/*
 * elfread.c
 *
 *  Created on: Jan 31, 2019
 *      Author: anlang
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

//https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

void*load_elf_prog(char*path, off_t*fsize)
{
    int fd;
    struct stat buf;
    void* mem = NULL;

    fd = open(path, O_EXCL, O_RDONLY);
    if (fd < 0) {
        goto OUT;
    }

    if (fstat(fd, &buf)) {
        goto CLOSE_FD;
    }

    if (fsize) {
        *fsize = buf.st_size;
    }

    mem = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    CLOSE_FD: {
        close(fd);
    }

    OUT: {
        return mem;
    }
}

#define LOG(str,...) printf(str,##__VA_ARGS__)

int print_elf_magic(unsigned char*magic, uint32_t size)
{
    uint32_t i;
    for (i = 0; i < size; ++i) {
        LOG(" %X", magic[i]);
    }
    LOG("\n");
    return 0;
}

int print_elf32_header(Elf32_Ehdr*hdr)
{
    return -1;
}

int print_elf_ABI(unsigned char abi, unsigned char version)
{
    LOG("Identifies the target operating system ABI.:\"");
    switch (abi)
    {
    case 0x00:
        LOG("System V");
        break;
    case 0x01:
        LOG("HP - UX");
        break;
    case 0x02:
        LOG("NetBSD");
        break;
    case 0x03:
        LOG("Linux");
        break;
    case 0x04:
        LOG("GNU Hurd");
        break;
    case 0x06:
        LOG("Solaris");
        break;
    case 0x07:
        LOG("AIX");
        break;
    case 0x08:
        LOG("IRIX");
        break;
    case 0x09:
        LOG("FreeBSD");
        break;
    case 0x0A:
        LOG("Tru64");
        break;
    case 0x0B:
        LOG("Novell Modesto");
        break;
    case 0x0C:
        LOG("OpenBSD");
        break;
    case 0x0D:
        LOG("OpenVMS");
        break;
    case 0x0E:
        LOG("NonStop Kernel");
        break;
    case 0x0F:
        LOG("AROS");
        break;
    case 0x10:
        LOG("Fenix OS");
        break;
    case 0x11:
        LOG("CloudABI");
        break;
    default:
        LOG("unkown");
    }
    LOG("\" version=%d\n", version);
    return 0;
}

int print_elf_object_file_type(uint16_t e_type)
{
    LOG("Identifies object file type:");
    switch (e_type)
    {
    case 0x00:
        LOG("ET_NONE");
        break;
    case 0x01:
        LOG("ET_REL");
        break;
    case 0x02:
        LOG("ET_EXEC");
        break;
    case 0x03:
        LOG("ET_DYN");
        break;
    case 0x04:
        LOG("ET_CORE");
        break;
    case 0xfe00:
        LOG("ET_LOOS");
        break;
    case 0xfeff:
        LOG("ET_HIOS");
        break;
    case 0xff00:
        LOG("ET_LOPROC");
        break;
    case 0xffff:
        LOG("ET_HIPROC");
        break;
    default:
        LOG("unkown");
        break;
    }
    LOG("\n");
    return 0;
}

int print_elf_machine(uint16_t machine)
{
    LOG("target instruction set architecture:");
    switch (machine)
    {
    case 0x00:
        LOG("No specific instruction set");
        break;
    case 0x02:
        LOG("SPARC");
        break;
    case 0x03:
        LOG("x86");
        break;
    case 0x08:
        LOG("MIPS");
        break;
    case 0x14:
        LOG("PowerPC");
        break;
    case 0x16:
        LOG("S390");
        break;
    case 0x28:
        LOG("ARM");
        break;
    case 0x2A:
        LOG("SuperH");
        break;
    case 0x32:
        LOG("IA-64");
        break;
    case 0x3E:
        LOG("x86-64");
        break;
    case 0xB7:
        LOG("AArch64");
        break;
    case 0xF3:
        LOG("RISC-V");
        break;
    default:
        LOG("unkown");
    }

    LOG("\n");
    return 0;
}

int print_elf64_header(Elf64_Ehdr*hdr)
{
    LOG("ELF HEADER:\n");
    LOG("Magic：");
    print_elf_magic(hdr->e_ident, sizeof(hdr->e_ident));
    LOG("ELF type(0X1=ELF32,0X2=ELF64):0X%X\n", hdr->e_ident[4]);
    LOG("DATA(0X1=\"little endianness\",0X2=\"big endianness\"):0X%X\n", hdr->e_ident[5]);
    LOG("version(magic):0X%X\n", hdr->e_ident[6]);
    print_elf_ABI(hdr->e_ident[7], hdr->e_ident[8]);
    LOG("PAD:0X%X, 0X%X, 0X%X, 0X%X, 0X%X, 0X%X, 0X%X\n", hdr->e_ident[9],
            hdr->e_ident[10], hdr->e_ident[11], hdr->e_ident[12],
            hdr->e_ident[13], hdr->e_ident[14], hdr->e_ident[15]);
    print_elf_object_file_type(hdr->e_type);
    print_elf_machine(hdr->e_machine);
    LOG("version:0X%X\n", hdr->e_version);
    LOG("entry address: %p\n", (void* )hdr->e_entry);
    LOG("program header table offset :0X%lX\n", hdr->e_phoff);
    LOG("section header table offset:0X%lX\n", hdr->e_shoff);
    LOG("processor-specific flags:0X%X\n", hdr->e_flags);
    LOG("program header entry size:%d\n", hdr->e_ehsize);
    LOG("number of program header entries:%d\n", hdr->e_phentsize);
    LOG("section header entry size:%d\n", hdr->e_phnum);
    LOG("number of section header entries:%d\n", hdr->e_shentsize);
    LOG("Number of section headers:%d\n", hdr->e_shnum);
    LOG("String table index:%d\n", hdr->e_shstrndx);

#if 0
    ELF 头：
    Magic： 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
    类别: ELF32
    数据: 2 补码，小端序 (little endian)
    版本: 1 (current)
    OS/ABI: UNIX - System V
    ABI 版本: 0
    类型: REL (可重定位文件)
    系统架构: Intel 80386
    版本: 0x1
    入口点地址： 0x0
    程序头起点： 0 (bytes into file)
    Start of section headers: 916 (bytes into file)
    标志： 0x0
    本头的大小： 52 (字节)
    程序头大小： 0 (字节)
    Number of program headers: 0
    节头大小： 40 (字节)
    节头数量： 14
    字符串表索引节头： 11
#endif
    return 0;
}

int print_elf_header(void*elf_header, off_t fsize)
{
    Elf32_Ehdr*hdr = elf_header;
    switch (hdr->e_ident[4])
    {
    case 0X01:
        if (fsize < sizeof(Elf32_Ehdr)) {
            return -1;
        }
        return print_elf32_header(elf_header);
    case 0X02:
        if (fsize < sizeof(Elf64_Ehdr)) {
            return -1;
        }
        return print_elf64_header(elf_header);
    default:
        return -1;
    }
}

int print_prog_type(uint32_t type)
{

    switch (type)
    {
    case PT_NULL:
        LOG("Program header table entry unused");
        break;
    case PT_LOAD:
        LOG("Loadable segment");
        break;
    case PT_DYNAMIC:
        LOG("Dynamic linking information");
        break;
    case PT_INTERP:
        LOG("Interpreter information");
        break;
    case PT_NOTE:
        LOG("Auxiliary information");
        break;
    case PT_SHLIB:
        LOG("reserved");
        break;
    case PT_PHDR:
        LOG("segment containing program header table itself");
        break;
    case PT_LOOS:
        LOG("PT_LOOS");
        break;
    case PT_HIOS:
        LOG("PT_HIOS");
        break;
    case PT_LOPROC:
        LOG("PT_LOPROC");
        break;
    case PT_HIPROC:
        LOG("PT_HIPROC");
        break;
    default:
        LOG("unkonow");
    }
    LOG("\n");
    return 0;
}

int print_prog_header(Elf64_Phdr*hdr)
{
    print_prog_type(hdr->p_type);
#if 0
    Elf64_Word p_flags;
    Elf64_Off p_offset; /* Segment file offset */
    Elf64_Addr p_vaddr; /* Segment virtual address */
    Elf64_Addr p_paddr; /* Segment physical address */
    Elf64_Xword p_filesz; /* Segment size in file */
    Elf64_Xword p_memsz; /* Segment size in memory */
    Elf64_Xword p_align; /* Segment alignment, file & memory */
#endif
    return 0;
}

int main(int argc, char**argv)
{
    off_t size;
    void*elf_prog;

    if (!(elf_prog = load_elf_prog(argv[1], &size))) {
        printf("load elf prog %s fail\n", argv[1]);
        return 1;
    }

    print_elf_header(elf_prog, size);
    print_prog_header(
            (Elf64_Phdr*) ((char*) elf_prog + ((Elf32_Ehdr*) elf_prog)->e_ehsize));
    return 0;
}
