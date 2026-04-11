#include "logger.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

// État interne du logger — static = visible uniquement dans ce fichier.
static log_level_t g_min_level = LOG_LEVEL_INFO;
static FILE       *g_out       = NULL;

// Convertit un niveau en chaîne de caractères pour l'affichage.
// Les espaces dans "INFO " et "WARN " alignent les colonnes.
static const char *level_label(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO ";
        case LOG_LEVEL_WARN:  return "WARN ";
        case LOG_LEVEL_ERROR: return "ERROR";
        default:              return "?????";
    }
}

void log_init(log_level_t min_level, const char *log_file) {
    g_min_level = min_level;

    if (log_file != NULL) {
        // "a" = append : on ne réécrit pas le fichier à chaque démarrage
        g_out = fopen(log_file, "a");
        if (g_out == NULL) {
            // Si l'ouverture échoue, on se rabat sur stdout
            fprintf(stderr, "[WARN ] Cannot open log file '%s', using stdout\n", log_file);
            g_out = stdout;
        }
    } else {
        g_out = stdout;
    }
}

void log_msg(log_level_t level, const char *fmt, ...) {
    // Filtre : on ignore les messages en dessous du niveau minimum
    if (level < g_min_level) return;

    // Sécurité : si log_init n'a pas été appelé, on écrit sur stdout quand même
    if (g_out == NULL) g_out = stdout;

    // Timestamp au format "YYYY-MM-DD HH:MM:SS"
    time_t     now = time(NULL);
    struct tm *t   = localtime(&now);
    char       ts[20];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);

    // Préfixe : [timestamp] [NIVEAU]
    fprintf(g_out, "[%s] [%s] ", ts, level_label(level));

    // Message avec ses arguments (même mécanique que printf)
    va_list args;
    va_start(args, fmt);
    vfprintf(g_out, fmt, args);
    va_end(args);

    fprintf(g_out, "\n");

    // fflush garantit que le message est écrit immédiatement,
    // même si le programme plante juste après.
    fflush(g_out);
}

void log_close(void) {
    if (g_out != NULL && g_out != stdout) {
        fclose(g_out);
        g_out = NULL;
    }
}
