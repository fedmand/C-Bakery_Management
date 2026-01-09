# Industrial Bakery Simulator (Discrete-Time) — C

Discrete-time simulation of an industrial bakery order-management system, developed for the **Algorithms and Data Structures** final exam (AY 2023–2024).  
**Final grade: 30/30 cum laude**.

The system models recipes, ingredient inventories with expiration, order processing, and periodic courier dispatch under capacity constraints. Time starts at 0 and advances by 1 after each processed command. All I/O strings are in **Italian** and must match the specification exactly.

---

## Build & Run
gcc Lode.c -o bakery

./bakery < input.txt > output.txt

## Input format
The first line contains two integers:
<corriere_periodicita> <corriere_capienza>

Each subsequent line is one command:
- aggiungi_ricetta <nome_ricetta> <ingrediente1> <q1> <ingrediente2> <q2> ...
- rimuovi_ricetta <nome_ricetta>
- rifornimento <ingrediente1> <q1> <scadenza1> <ingrediente2> <q2> <scadenza2> ...
- ordine <nome_ricetta> <numero_elementi_ordinati>

## System rules:
Ingredients are stored in lots with quantity and expiry time and are consumed by earliest-expiry-first. Orders are prepared only if all required ingredients are available in full; otherwise they are queued FIFO and re-evaluated after restocks. The courier loads only complete orders within its gram-capacity, selecting the longest feasible prefix by arrival time and loading by descending order weight (tie-break by earlier arrival).

## Implementation notes:
Hash tables are used for recipes and ingredient inventories. Ingredient lots are kept ordered by expiry. Recipes store direct references to ingredient batches. Pending and ready orders are handled with separate data structures. Expiry handling and order rechecks are optimised to meet worst-case constraints.

## Files:
Lode.c — complete implementation  
Specifica.pdf — assignment specification (Italian)
