#include <stdlib.h>
       
void source_4(int n, char *buff_to_taint){
    socketfd = socket(AF_INET, SOCK_STREAM, 0);
    // Would normally bind and open socket or some such steps, but
    // skipping for simplicity
    recv(socketfd, buff_to_taint, n, 0);

}

int main(){
   int n = 1024;
   char buff[1024];
   source_4(n, buff)
   system(buff);
}