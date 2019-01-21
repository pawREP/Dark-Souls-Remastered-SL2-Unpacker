#include <iostream>
#include <string>
#include <fstream>
#include "aes.hpp"

const unsigned int USER_DATA_SIZE = 0x060020;
const unsigned char KEY[AES_KEYLEN] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

void DecryptSaveSlot(char* save_slot_buffer) {
    unsigned char IV[AES_BLOCKLEN];
    memcpy(IV, save_slot_buffer, AES_BLOCKLEN);

    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, KEY, IV);
    AES_CBC_decrypt_buffer(&ctx, reinterpret_cast<uint8_t*>(save_slot_buffer) + AES_BLOCKLEN, USER_DATA_SIZE);
}

void Exit(std::string msg, int ret = EXIT_FAILURE) {
    printf("%s \n\nPress Enter to exit.", msg.c_str());
    std::cin.ignore();
    exit(ret);
}

int main(int argc, char *argv[])
{
    const unsigned int SAVE_FILE_SIZE = 0x4204D0;
    const unsigned int SAVE_SLOT_SIZE = 0x060030;
    const unsigned int BASE_SLOT_OFFSET = 0x02C0;
    const unsigned int USER_DATA_FILE_CNT = 11;
    const unsigned int USER_DATA_FILE_NAME_LEN = 13;

    char* save_file_buffer = new char[SAVE_FILE_SIZE];

    printf("----------------------------\n");
    printf("B3's DSR save file unpacker.\n");
    printf("----------------------------\n\n");

    if (argc == 1)
        Exit("No input input file.");

    std::ifstream ifs(argv[1], std::ifstream::binary);
    if (!ifs.is_open())
        Exit("Failed to open input file.");

    ifs.read(save_file_buffer, SAVE_FILE_SIZE);
    if (ifs.fail())
        Exit("Input file too small.");
    ifs.close();

    printf("Unpacking... ");

    for (int i = 0; i < USER_DATA_FILE_CNT; i++) {
        char* current_save_slot_pointer = save_file_buffer + BASE_SLOT_OFFSET + i * SAVE_SLOT_SIZE;
        DecryptSaveSlot(current_save_slot_pointer);

        char user_data_file_name[USER_DATA_FILE_NAME_LEN];
        sprintf_s(user_data_file_name, USER_DATA_FILE_NAME_LEN, "USER_DATA%03d", i);

        std::ofstream ofs(user_data_file_name, std::ofstream::binary);
        if (!ofs.is_open())
            Exit("Failed to open USER_DATA file.");

        ofs.write(current_save_slot_pointer + AES_BLOCKLEN, USER_DATA_SIZE);
        ofs.close();

        if (ofs.bad())
            Exit("Writing USER_DATA failed.");
    }

    Exit("Success!", EXIT_SUCCESS);
}

