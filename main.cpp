#include <windows.h>
#include <stdio.h>
#include <string.h>

// main code
int main(VOID) {

    // payload shellcode que je comprends pas encore tres bien
    // tout ce que je sais c'est que ca demarre notepad
    unsigned char shellcode_payload[196] = {
        0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5, 0x31, 0xC0, 0x64,
        0x8B, 0x50, 0x30, 0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14, 0x8B, 0x72, 0x28,
        0x0F, 0xB7, 0x4A, 0x26, 0x31, 0xFF, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C,
        0x20, 0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0xE2, 0xF2, 0x52, 0x57, 0x8B, 0x52,
        0x10, 0x8B, 0x4A, 0x3C, 0x8B, 0x4C, 0x11, 0x78, 0xE3, 0x48, 0x01, 0xD1,
        0x51, 0x8B, 0x59, 0x20, 0x01, 0xD3, 0x8B, 0x49, 0x18, 0xE3, 0x3A, 0x49,
        0x8B, 0x34, 0x8B, 0x01, 0xD6, 0x31, 0xFF, 0xAC, 0xC1, 0xCF, 0x0D, 0x01,
        0xC7, 0x38, 0xE0, 0x75, 0xF6, 0x03, 0x7D, 0xF8, 0x3B, 0x7D, 0x24, 0x75,
        0xE4, 0x58, 0x8B, 0x58, 0x24, 0x01, 0xD3, 0x66, 0x8B, 0x0C, 0x4B, 0x8B,
        0x58, 0x1C, 0x01, 0xD3, 0x8B, 0x04, 0x8B, 0x01, 0xD0, 0x89, 0x44, 0x24,
        0x24, 0x5B, 0x5B, 0x61, 0x59, 0x5A, 0x51, 0xFF, 0xE0, 0x5F, 0x5F, 0x5A,
        0x8B, 0x12, 0xEB, 0x8D, 0x5D, 0x6A, 0x01, 0x8D, 0x85, 0xB2, 0x00, 0x00,
        0x00, 0x50, 0x68, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D,
        0x2A, 0x0A, 0x68, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x3C, 0x06, 0x7C,
        0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A,
        0x00, 0x53, 0xFF, 0xD5, 0x6E, 0x6F, 0x74, 0x65, 0x70, 0x61, 0x64, 0x2E,
        0x65, 0x78, 0x65, 0x00
    };

    //definition de la taille de la payload pour pouvoir l'inscrire en memoire
    unsigned int shellcode_length = sizeof(shellcode_payload);
    

    //allouer de la memoire pour que je puisse executé mon programme

    //learn.microsoft.com/fr-fr/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    //lpAddress -> 0/NULL pour laisser au systeme l'endroit où est alloué la region
    //dwSize -> taille de la région
    //flAllocationType ->   MEM_COMMIT: assure que le contenu de la region alloué est mis a 0 et garanti une allocation physique
    //                      MEM_RESERVE: juste pour reserver une plage de l'adresse 
    //flProtect ->  lors de l'allocation ca doit etre en PAGE_READWRITE ou bien PAGE_EXECUTE_READWRITE
    //              d'apres ce que j'ai compris je vais devoir changer pour rendre le contenu de la région executable

    LPVOID process_memory_address = VirtualAlloc(0, shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (process_memory_address == NULL) {
        return 0;
    }

    //déplace mon shellcode dans la memoire qu'on vient d'allouer
    // _Out_ -> destination
    // _In_ -> source
    // _In_ -> taille de la source; si la taille est plus grande que celle qu'on a allouer ?? violation d'acces j'imagine ?!
    //learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
    RtlMoveMemory(process_memory_address, shellcode_payload, shellcode_length);

    //DEP protection, je dois modifier 
    //rends le shellcode executable
    //lpAddress -> adresse de mon shellcode
    //dwSize -> taille; si la taille est plus grande ??
    //flNewProtect ->   nouvelle protection/type; PAGE_EXECUTE
    //                  learn.microsoft.com/fr-fr/windows/win32/Memory/memory-protection-constants

    //lpflOldProtect -> permet d'enregister les anciennes permissions pour pouvoir y revenir si besoin
    DWORD old_protection = 0;
    BOOL returned_vp = VirtualProtect(process_memory_address, shellcode_length, PAGE_EXECUTE, &old_protection);

    // execute thread
    if (returned_vp != NULL) {
        //lpThreadAttributes -> pas trop compris mais ok
        //dwStackSize -> NULL; par défaut sur windows 1MB; y'a des programmes ou je pourrais avoir besoin de plus ??
        //LPTHREAD_START_ROUTINE -> process adress, là ou je vais commencer a executé en gros
        //lpParameter -> NULL; j'ai pas de donné à passer en parametre
        //dwCreationFlags -> NULL;  si j'ai bien compris ca pourrait permettre de mettre mon thread en attente; en attente comment ?? 
        //                          ca veut dire que je pourrais le récupérer plus tard et l'exec ?
        //lpThreadId -> pour récuperer le thread id d'apres ce que j'ai compris

        HANDLE thread_handle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)process_memory_address, NULL, NULL, NULL);

        //permet d'attendre que le programe tourne de ce que j'ai compris j'avoue que c'est un peu flou
        WaitForSingleObject(thread_handle, INFINITE);
        CloseHandle(thread_handle);
    }
}