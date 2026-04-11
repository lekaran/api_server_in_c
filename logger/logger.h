#ifndef LOGGER_H
#define LOGGER_H

// Les niveaux de log, ordonnés du moins grave au plus grave.
// "Ordonné" est important : ça permet de filtrer avec un simple >= .
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

// Initialise le logger.
// min_level : niveau minimum affiché (ex: LOG_LEVEL_INFO filtre les DEBUG)
// log_file  : chemin vers un fichier de log, ou NULL pour écrire sur stdout
void log_init(log_level_t min_level, const char *log_file);

// Écrit un message. Utilisé en interne par les macros ci-dessous.
void log_msg(log_level_t level, const char *fmt, ...);

// Ferme le fichier de log si un fichier a été ouvert.
void log_close(void);

// Macros pratiques — à utiliser dans le code à la place de printf.
// Le ##__VA_ARGS__ gère le cas où il n'y a pas d'arguments variadiques.
#define LOG_DEBUG(fmt, ...) log_msg(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_msg(LOG_LEVEL_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_msg(LOG_LEVEL_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_msg(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

#endif
