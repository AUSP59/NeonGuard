#include <iostream>
#include "neonsec/core.hpp"
int main(){
    std::cout << "neonsec ci ok: " << neonsec::sum(5, 7) << std::endl;
    return neonsec::sum(5, 7)==12 ? 0 : 1;
}