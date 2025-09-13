// C vulnerability test file
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buffer[100];
    char *input = argv[1];
    
    // Buffer overflow vulnerabilities
    strcpy(buffer, input);                    // Line 10
    strcat(buffer, " suffix");               // Line 11
    sprintf(buffer, "User: %s", input);      // Line 12
    
    // Dangerous input functions
    printf("Enter data: ");
    gets(buffer);                            // Line 16
    scanf("%s", buffer);                     // Line 17
    
    // Format string vulnerability  
    printf(input);                           // Line 20
    
    // Command injection
    system(input);                           // Line 23
    
    // Memory management issues
    char *ptr = malloc(100);                 // Line 26
    free(ptr);                              // Line 27
    
    // Unsafe memory operations
    memcpy(buffer, input, 200);             // Line 30 - copies more than buffer size
    
    // Weak randomness
    int random = rand();                     // Line 33
    
    return 0;
}