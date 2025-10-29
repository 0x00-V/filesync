#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <chrono>
#include <format>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/md5.h>


std::string md5_file(const std::string& filename){
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()){
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Could not open file: " + filename);
    }

    const std::size_t bufferSize = 4096;
    char buffer[bufferSize];
    while (file.good()){
        file.read(buffer, bufferSize);
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0){
            EVP_DigestUpdate(ctx, buffer, bytesRead);
        }
    }

    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < length; i++){
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}

int main() {
    std::string filename = "test.txt";
    try{
        std::string hash = md5_file(filename);
        std::cout << filename << " MD5: " << hash << '\n';

        auto ftime = std::filesystem::last_write_time(filename);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - decltype(ftime)::clock::now() + std::chrono::system_clock::now()
        );
        std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);
        std::cout << "File write time is "
                  << std::put_time(std::localtime(&cftime), "%F %T") << '\n';

    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
    return 0;
}

