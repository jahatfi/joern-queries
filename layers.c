#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#include<sys/socket.h>
#include<unistd.h>
#include "defs.h"
//#include "test.h"

//Verfiy preprocessing is performed
#define PI 3.14
int global_int = 6;

//Function prototypes (normally in a .h file)
char source_1();
int source_2(int z);
void source_3(char *buff, int len);
int layer_1_a(int a, char *buff);
int layer_1_b(bool flag, char *buff, float c, double d);
void layer_1_c(char * buff, int b);
int layer_2_a(char *buff, bool flag);
bool layer_2_b(char * buff, int myInt);
char * layer_2_c(char * buff, bool flag);
bool layer_3_a(char * buff, int count, bool flag);
int layer_3_b(bool flag, char *buff);
void sink_1(char * buff);
void sink_2(char * buff);
void sink_3();
//void sink_4();

char * return_tainted_buff(){
    //Allocate a buffer on the heap.  Taint it, the return it.
    char * tainted_buff_ptr = NULL;
    int size = 1024 * 2;
    tainted_buff_ptr = (char *) malloc(size*sizeof(char));
    if (!tainted_buff_ptr) return NULL;
    gets(tainted_buff_ptr);
    return tainted_buff_ptr;
}

void readme(int a){
    int b = a;
    system(b);
}

//Begin source functions
char *
source_1 (){
    /* A test */ /*Another test */ /*Another test */     /* A test */ /*Another test */ /*Another test */

   char *data;
   char buff[100];
   char buff2[100];
   char buff3[100];
   int a, b;  //Tests that I can parse variables declared on the same line
   float c;
   int d = rand();
   int e = rand();
   float pi = PI;  //Test macro expansion
   float tau = TAU;//Test inclusion of macro def from external file
   bool flag;
   double myDouble;
   char *myBuff;
   //Will return buff[0].  Want to be sure that it's initialized.
   buff[0] = 'A';
   goto test_label;
   return 'E';  //Should never be reached
   test_label:
   {
       int test;
       //This is a plain block idiom.  You SHOULD see this in the resulting file, but it should NOT be indented.
   }
   printf("Enter some data (< 100 chars):\n");
   gets(buff);
   //fgets(buff, d, a);
   goto test_label_1;
   printf("This should not be printed.");
   test_label_1:
   if(1 == 1){
       printf("I must be here!\n"); //This line must not be removed from a path
   }
   if(d < 0){
      layer_1_a (a,buff);           //Test whitespace between predicate and '('
   }
   if(e > 0) layer_1_b(flag, buff, c, myDouble);
   layer_1_c(buff, e);
   return buff;
}
//Testing conditional compilation
#define CONCOM
#ifdef CONCOM
    int
    source_2(int z)
    {
    int a = z;
    int b;
    int i = 0;
    int numBytes;
    int socketfd = 1;
    int buffSize = 256;
    char *myBuff;
    char myBuff2[512];
    bool flag = false;
    float f = 4.5;
    double d = 1.2;
    socketfd = socket(AF_INET, SOCK_STREAM, 0);
    for(i = 0; i++; i < 10){
            //numBytes = recv(socketfd, myBuff2, buffSize, 0);
            numBytes = read(socketfd, myBuff2, buffSize);            
            myBuff = (char *)&myBuff2;
            //Call layer1 function
            layer_1_b(flag, myBuff, f, d);
    }
    return numBytes;
    }
#endif

//===========================================================
void source_3(char *source_3_buff, int len){
    int a;
    int count;
    int numBytes;
    int file_fd = 1;

    //printf("Enter some data fewer than %d chars\n",len);
    //numBytes = read(stdin, buff, len);
    //Call layer1 function
    gets(source_3_buff);
}

void source_4(int n, char *buff_to_taint){
    socketfd = socket(AF_INET, SOCK_STREAM, 0);
    // Would normally bind and open socket or some such steps, but
    // skipping for simplicity
    recv(socketfd, buff_to_taint, n, 0);

}

//==============================================================================
//This is a dead end
int layer_1_a(int a, char *buff){
   int x = rand();
   int i = 0;
   float y = 3.14;
   if(buff[0] == 'A'){
       printf("The first char is 'A'\n");
       printf("x: %d\n", x);
   }
   else{

       printf("The first char is not 'A'\n");
       printf("y: %f\n", y);
   }
   printf("Hmm"); for(i = 0; i < 5; i++){
      printf("Hi\n");
   }
   return 0;
}
//==============================================================================
//Not a dead end
int
layer_1_b(bool flag,
          char *buff,
          float c,
          double d)
          {
   double myDouble;
   char *newBuff;
   //Call layer2
   if(c > 75){
       if(d <= 4){
           printf("d Must be greater than 4.\n");
           if(d <= 6){
               printf("A totally unecessary level of nested code.\n  This should get removed.");
           }
           return -1;
       }
       else{
           printf("Success: Yes.\n");
           layer_2_b(buff, flag);
           return 0;
       }
   }

   else{
       printf("C must exceed 75.\n");
       return -2;
   }

}
//==============================================================================
//This is not a dead end
void layer_1_c(char * buff, int b){
    char myChar;
    bool flag;
    if(b <  0) return;
    if(b >= 0 && b <= 50){
        //Call layer2
        flag = layer_2_b(buff, b);
    }
    if(b > 50){
       if(b < 250 ){
           //Call layer2
           flag = layer_2_c(buff, flag);
       }
       else{
           printf("b must be less than 250.\n");
       }
    }
    else return;
}

//Begin layer 2 functions

//A dead end
int layer_2_a(char *buff, bool flag){
    if(!flag){
        return 1;
    }
    if((char)buff[1] == 'B'){
        printf("2nd char of Buff is 'B'");
    }
    return 0;
}
//==============================================================================
//Not a dead end
bool layer_2_b(char * buff, int myInt){
    int count = rand();
    int randNum1 = rand();
    bool flag = false;

    if(randNum1 < 5) flag = true;

    if(flag){
       if(count <= 5){
          printf("Count must be greater than 5.\n");
       }
       else{
           layer_3_a(buff, count, flag);
       }
    }
    else printf("Flag must be true.\n");

    return flag;
}

//Also not a dead end
char * layer_2_c(char * buff, bool flag){
   if(flag){
       layer_3_b(flag, buff);
   }
}
//==============================================================================
//Begin layer 3 functions
bool layer_3_a(char * buff, int count, bool flag){

   if(count > 128){
      if(flag){
          printf("Flag must be false.\n");
          return false;
      }
      else if(count > 64){
          sink_1(buff);
          return true;
      }
   }
}
//==============================================================================
int layer_3_b(bool flag, char *buff){
   srand(100);
   int myVar = rand();
   if(myVar <= 10000){
      if(myVar <= 0){
          printf("myVar must be greater than 0\n");
          return -1;
      }
      else{
          sink_1(buff);
          return 0;
      }
   }
   //Dead code here
   switch(myVar){
       case 0:
          printf("hi");
       case 1:
          sink_2(buff);
          break;
       case 2:
          sink_1(buff);
          break;
       default:
          break;
   }
}
//==============================================================================

//Simple sink function
void sink_1(char * buff){
    system(buff);
    return;
}
//==============================================================================

//Simple sink function
void sink_2(char * buff){
    char dest[100];
    sprintf(dest, "%s", buff);
    //system(buff);
    return;
}
//==============================================================================

void sink_3(){
    //Unreachable.  Should be excluded.
    char buff[100];
    gets(buff);
    system(buff);
}
//==============================================================================
void sink_4(char* buff, int len){
    char dest[100];
    memcpy(dest, buff, len);
}
//==============================================================================

void main (int argc, char * argv[]){
    //TODO Taint a struct, and some dynamically allocated memory

    // Path #1 is simply the next 3 lines
    char * buff1 = return_tainted_buff();
    system(buff1);
    free(buff1);

    // Path #2 is simply the next 4 lines
    int len = 256;
    char buff[len];
    source_3(buff, len);
    system(buff);

    // Path #3
    char buff4[len];
    source_4(len, buff4);
    system(buff_to_taint);

    printf("The global int is %d\n", global_int);
    int i;
    i++;
    i--;
    ++i;
    i--;
    int my_int, my_int2;    



    strcpy(buff, argv[1]); 
    for(i = 0; i < len; i++){
        buff[i] = (char) my_int;

    }    
    int (*source_2_ptr)(int) = &source_2;
  
    if(1){
        if(0){
            printf("Dead code\n");
        }
    }

    printf("Testing...\n");
    source_1();
    //source_2(1);
    (*source_2)(1);  //SIFT appears to work with function pointers
    source_3(buff, len);

    strcpy(buff, argv[1]);  //This is bad code.
    fscanf(stdin, "%d%d", &my_int, &my_int2); 
    readme(my_int);

    my_int2 = len; //my_int2 is sanitized here via constant overwrite
    sink_4(buff, my_int);


    if(my_int) len = my_int;
    if(buff[0]) len = my_int2;
    printf("Done.\n");
    return;
}
//==============================================================================




/* Need to account for various styles
    The following are different styles to take into account:
    1. Placement of return type         (same line T1__ or line above  T2__ )
    2. Placement of parameters          (same line T_1_ or one each    T_2_ )
    3. Placement of opening bracket '{' (same line T__1 or line below  T__2)

    T1__:
        T111: int foo(...){
        T112: int foo(...)
              {
        T121: int foo(.
                .
                .){
        T122: int foo(.
                .
                .)
                {
    T2__:
        T211:   int
                foo(...){
        T212:   int
                foo(...)
                {
        T221:   int
                foo(.
                .
                .){
        T222:   int
                foo(.
                .
                .)
                {
    Also note that all code in a .c file may not be function definitions.
    There may be structions, enums, etc.
    e.g.

    void foo(){}

    enum modes { MODE_INVALID, MODE_CHUNKED, MODE_ADDSTUFF, MODE_NORMAL };

    const struct {
        const enum modes mode;
        const char * text;
    } modes_array[] = {
        {MODE_CHUNKED, "chunked"},
        {MODE_ADDSTUFF, "addstuff"},
        {MODE_NORMAL, "normal"},
        {MODE_INVALID, NULL}
    };

    int bar(){}
*/


