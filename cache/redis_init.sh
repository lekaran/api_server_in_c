#!/bin/bash

# Lancer Redis en arrière-plan
redis-server --requirepass ${REDIS_ROOT_PASSWORD} &

# Attendre que Redis soit prêt
echo "Attente du démarrage de Redis..."
until redis-cli -a ${REDIS_ROOT_PASSWORD} ping 2>/dev/null; do
  sleep 1
done

echo "Redis est prêt ! Configuration de l'utilisateur ACL..."

# Créer l'utilisateur - CORRECTEMENT cette fois !
redis-cli -a ${REDIS_ROOT_PASSWORD} ACL SETUSER ${REDIS_USER} on ">${REDIS_PASSWORD}" ~* +@all

echo "Utilisateur ${REDIS_USER} créé avec succès !"

# Garder le container en vie
wait