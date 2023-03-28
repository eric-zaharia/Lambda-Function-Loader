README Hackaton Decembrie 2022,

Zaharia Eric-Alexandru, Leanca Radu Marian


Am implementat un lambda loader pe arhitectura client-server folosind socketi UNIX.
Am inceput prin a implementa functiile din ipc.h pentru managementul socketilor clientului
si ai serverului. 


===Implementare server===

Apoi am configurat serverul sa astepte conexiuni de la clienti si sa le accepte cand
le primeste. Mai intai umplem campurile structurii lib cu biblioteca, functia si
parametrii apelati si apoi apelam lib_run. Am intampinat mai multe probleme
in implementarea serverului, fiind si prima oara cand lucram cu socketi, insa am reusit
usor usor sa ajungem la o solutie.


===Implementare loader===

In prehooks cream fisierul in care urmeaza sa scriem datele de la stdout.
Apoi in execute load-uim biblioteca si datele corespunzatoare urmand a rula executabilele
si a scrie in fisier output-ul de la stdout. Facem acest lucru prin apeluri la dup si dup2
pentru a redirecta tot ce ajunge in stdout spre fisierul tinta.

In cazul in care nu exista biblioteca sau functia, tratam aceste cazuri prin parsarea erorilor 
si se iese din functie. De asemenea, completam campul de handle cu ajutorul dlopen.
Pentru a gasi adresa functiei folosim dlsym si verificam daca exista parametri pentru functie, 
astfel apeland functia ceruta cu parametri dati.


===Paralelizare===

Pentru a paraleliza am folosit thread-uri, pasandu-le tot ce inseamna deschiderea conexiunii
intre client si server si incarcare a bibliotecii, cat si rularea functiilor din biblioteca.
Acestea permit prelucrarea mai multor clienti in acelasi timp.


===Concluzie===

A fost o experienta foarte interesanta si chiar ne-a facut placere sa lucram la acest proiect,
care, cu siguranta, ne-a adus multe obstacole, dar peste multe am reusit sa trecem.


Va multumim pentru aceasta experienta inedita!
