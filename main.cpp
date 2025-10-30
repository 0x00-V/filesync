#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <iomanip>

#include <openssl/evp.h>


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


int main() {
  try{
    std::string filename = "test.txt";
    std::string hash = returnFileSha1(filename);
    std::cout << "SHA1(" << filename << ") - " << hash << '\n';
  } catch(const std::exception& e){
    std::cerr << "Error: " << e.what() << '\n';
  }
  return 0;
}

