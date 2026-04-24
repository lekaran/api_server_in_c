#include "dotenv.h"
#include "../logger/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

int load_env_file(const char *filename){
    // Open the .env file
    FILE *fptr = fopen(filename,"r");
    if(fptr == NULL){
        LOG_ERROR("There is probleme when the program try to open the ENV file : %s \n", strerror(errno));
        return -1;
    }

    // parse the env file then setenv for each variable in it.
    char *line = (char *)malloc(MAX_LENGTH);
    if(line == NULL){
        LOG_ERROR("There is a probleme when the program try to reserve memory : %s \n", strerror(errno));
        // Close the .env file
        int close_file = fclose(fptr);
        if(close_file == EOF){
            LOG_ERROR("There is probleme when the program try to close the ENV file : %s \n", strerror(errno));
            return -1;
        }
        return -1;
    }

    while (fgets(line, MAX_LENGTH, fptr)){
        if(line[0] == '#' || (line[0] == '/' && line[1] == '/' ) || line[0] == '\n'){ // skip if the ligne is a comment or empty ligne
            continue;
        }

        char *var=strchr(line,'='); // skip if the line don't has the '='
        if(var == NULL){
            continue;
        }
        
        *var='\0';
        char *key = line;
        char *value = var+1;

        // make sure that the KEY is good
        for (size_t i = 0; key[i] != '\0'; i++){
            if(isspace(key[i])){
                LOG_ERROR("There are a problem on the key in the ENV!\n");
                // free memory
                free(line);
                // Close the .env file
                int close_file = fclose(fptr);
                if(close_file == EOF){
                    LOG_ERROR("There is probleme when the program try to close the ENV file : %s \n", strerror(errno));
                    return -1;
                }
                return -1;
            }
        }
        
        // stop the value at the end of the line
        char *newValue=strchr(value,'\n'); // skip if the line don't has the '='
        if(newValue != NULL){
            *newValue='\0';
        }

        // 
        int load_env = setenv(key, value, 1);
        if(load_env == -1){
            LOG_ERROR("There are a problem when the program try to load the env variable : %s \n", strerror(errno));
            // free memory
            free(line);
            // Close the .env file
            int close_file = fclose(fptr);
            if(close_file == EOF){
                LOG_ERROR("There is probleme when the program try to close the ENV file : %s \n", strerror(errno));
                return -1;
            }
            return -1;
        }
    }
    
    // free memory
    free(line);
    // Close the .env file
    int close_file = fclose(fptr);
    if(close_file == EOF){
        LOG_ERROR("There is probleme when the program try to close the ENV file : %s \n", strerror(errno));
        return -1;
    }
    return 0;
}
