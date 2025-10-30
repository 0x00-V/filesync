#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <map>
#include <openssl/evp.h>

struct indexedFile{
  std::filesystem::path path;
  std::filesystem::file_time_type lastWrite;
};


std::map<std::string, indexedFile> folder1_map;
std::map<std::string, indexedFile> folder2_map;


std::string makeSHA1evp(const char* text, size_t text_len)
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  md = EVP_sha1();
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, text, text_len);

  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_free(mdctx);
  std::ostringstream oss;
  for(unsigned int i = 0; i < md_len; i++){
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
  }
  return oss.str();
}

std::string returnFileSha1(const std::string& filename)
{
  const EVP_MD* md = EVP_sha1();
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);

  std::ifstream file(filename, std::ios::binary);
  if(!file){
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("Couldn't open " + filename + ".\n");
  }
  
  std::vector<char> buffer(4096);
  while(file.good()){
    file.read(buffer.data(), buffer.size());
    std::streamsize bytesRead = file.gcount();
    if(bytesRead > 0){
      EVP_DigestUpdate(mdctx, buffer.data(), bytesRead);
    }
  }
  unsigned char md_val[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  EVP_DigestFinal_ex(mdctx, md_val, &md_len);
  EVP_MD_CTX_free(mdctx);

  std::ostringstream oss;
  for(unsigned int i = 0; i < md_len; i++){
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_val[i]);
  }
  return oss.str();
}

void recursiveItems(int folder_num, const std::filesystem::path& path){
  try{
    for(const auto& item : std::filesystem::directory_iterator(path)){
      if(item.is_regular_file()){
        //std::cout << item.path() << " -> " << returnFileSha1(item.path().string()) << '\n';
        if(folder_num == 1){
          folder1_map[returnFileSha1(item.path().string())] = indexedFile{item.path(), std::filesystem::last_write_time(item.path())};
        }else if (folder_num == 2) {
          folder2_map[returnFileSha1(item.path().string())] = indexedFile{item.path(), std::filesystem::last_write_time(item.path())};
        }
      } else if(item.is_directory()){
        //std::cout << "Directory: " << item.path() << '\n';
        recursiveItems(folder_num, item.path());
      }
     
    }
  }catch(const std::exception& e){
    std::cerr << "Error: " << e.what() << '\n';
  }

}


void compareItems(std::filesystem::path& folder1, std::filesystem::path& folder2){
  try{
    std::cout << "\n\nFolder 1:\n";
    for(const auto& e1 : std::filesystem::directory_iterator(folder1)){
      if(e1.is_regular_file()){
        folder1_map[returnFileSha1(e1.path().string())] = indexedFile{e1.path(), std::filesystem::last_write_time(e1.path())};
      } else if(e1.is_directory()){
        std::cout << "Exploring Directory: " << e1.path() << '\n';
        recursiveItems(1, e1.path());
      }
    }

    std::cout << "\n\nFolder 2:\n";
    for(const auto& e2 : std::filesystem::directory_iterator(folder2)){
      if(e2.is_regular_file()){
        folder2_map[returnFileSha1(e2.path().string())] = indexedFile{e2.path(), std::filesystem::last_write_time(e2.path())};
      } else if(e2.is_directory()){
        std::cout << "Exploring Directory: " << e2.path() << '\n';
        recursiveItems(2, e2.path());
      }
    }
    std::cout << "\n\n";
  }catch(const std::exception& e){
    std::cerr << "Error: " << e.what() << '\n';
  }
}

int main() {
  std::filesystem::path folder1 = "./testfolder1/";
  std::filesystem::path folder2 = "./testfolder2/";
  compareItems(folder1, folder2);

  auto to_time_t = [](auto ftime) {
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(ftime - decltype(ftime)::clock::now() + std::chrono::system_clock::now());
    return std::chrono::system_clock::to_time_t(sctp);
  };

  for (const auto& [f1_key, f1_value] : folder1_map){
    auto it = folder2_map.find(f1_key);
    if(it != folder2_map.end()) {
      const auto& f2_value = it->second;
      if (f1_value.lastWrite > f2_value.lastWrite) {
          std::cout << f1_value.path.filename() << " is newer in folder1\n";
      } else if (f1_value.lastWrite < f2_value.lastWrite) {
          std::cout << f2_value.path.filename() << " is newer in folder2\n";
      } else {
          std::cout << f1_value.path.filename() << " files in sync\n";
      }
    }
  }
  
  for (const auto& [f1_key, f1_value] : folder1_map){
    if (folder2_map.find(f1_key) == folder2_map.end()) {
        std::cout << f1_value.path << " exists only in folder1\n";
    }
  }
  for (const auto& [f2_key, f2_value] : folder2_map){
    if (folder1_map.find(f2_key) == folder1_map.end()) {
        std::cout << f2_value.path << " exists only in folder2\n";
    }
  }



  return 0;
}
