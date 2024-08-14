Surveillance et détection des attaques de type DDoS via le nombre de paquets entrants sur la carte réseau du serveur. 

Si le seuil de paquets transitant par la carte réseau indiqué est atteint (seuil modulable), seuil anormalement élevé par rapport aux opérations standars des activités quotidiennes, le programme va créer une entrée sur IPTABLES,
le firewall embarqué des systèmes unix/linux, pour dropper les paquets. 
Mais avant, le programme vérifie que l'entrée n'existe pas avant toute nouvelle injection IPTABLES.

Dès détection de l'attaque, le programme envoi une notification d'alerte à l'administrateur par API sécurisée TELEGRAM dans un groupe chatbot préalablement crée pour la circonstance.
Tous les évènement sont logués dans le fichier de log ddos_protection.log
