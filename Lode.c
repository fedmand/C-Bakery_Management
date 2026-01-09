#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 65536
#define BUCKET_SIZE 200
#define LIST_INIT_CAPACITY 1

#define ADD_RECIPE_MSG "aggiungi_ricetta"
#define REMOVE_RECIPE_MSG "rimuovi_ricetta"
#define RESTOCK_MSG "rifornimento"
#define ORDER_MSG "ordine"
#define INVALID_OP_MSG "Errore: Operazione non valida\n"
#define IGNORED_MSG "ignorato\n"
#define ADDED_MSG "aggiunta\n"
#define PENDING_ORDERS_MSG "ordini in sospeso\n"
#define REMOVED_MSG "rimossa\n"
#define NOT_PRESENT_MSG "non presente\n"
#define RESTOCKED_MSG "rifornito\n"
#define ACCEPTED_MSG "accettato\n"
#define REJECTED_MSG "rifiutato\n"
#define EMPTY_TRUCK_MSG "camioncino vuoto\n"

typedef void (*FreeOperation)(void *);

typedef int (*Sorter)(void *, void *);

typedef int (*KeyComparator)(void *, void *);

typedef unsigned long long int (*HashFunction)(void *);

typedef struct {
    void **data;
    unsigned size;
    unsigned capacity;

    FreeOperation free_op;
} List;

typedef struct MapNode {
    void *key;
    void *value;
    struct MapNode *next;
} MapNode;

typedef struct {
    int count;
    MapNode *array[BUCKET_SIZE];

    HashFunction hash_func;
    KeyComparator key_cmp;
    FreeOperation free_op;
} Map;

typedef struct {
    Map *mp;
    int bucketIndex;
    MapNode *current;
} MapIterator;

typedef enum {
    ADD_RECIPE,
    REMOVE_RECIPE,
    RESTOCK,
    ORDER,
    INVALID
} OperationType;

typedef struct {
    OperationType type;
    char *recipe_name;
    List ingredients;
    List quantities;
    List expiration_times;
    unsigned quantity;
} Input;

typedef struct {
    unsigned expiration_time;
    unsigned quantity;
} Packet;

typedef struct {
    char *ingredient;
    List packets; // <Packet>
    unsigned total_quantity;
} Batch;

typedef struct {
    char *name;
    List ingredient_batches; // <Batch*>
    List ingredient_quantities; // <unsigned>

} Recipe;

typedef struct {
    Recipe *recipe;
    unsigned arrival_time;
    unsigned quantity;
    unsigned weight;

    Batch *missing_batch;
    unsigned missing_quantity;
} Order;

typedef struct {
    unsigned period;
    unsigned capacity;
    unsigned next_arrival_time;
} Courier;

typedef struct {
    unsigned current_time;
    Map recipes; // <Recipe>
    List pending_orders; // <Order>
    List queued_orders; // <Order>
    Map batches; // <Batch>
    Courier courier;
    unsigned next_expiry_check;
} Bakery;

void list_init(List *list, FreeOperation free_op);

void list_add_back(List *list, void *data);

void list_add_sorted(List *list, void *data, Sorter cmp);

void list_remove(List *list, void *data);

void list_pop_front(List *list);

void *list_get(List *list, unsigned index);

void free_list(List *list);

void list_reset(List *list);

void map_init(Map *mp, KeyComparator key_comparator, HashFunction hash_func, FreeOperation free_op);

void map_insert(Map *mp, void *key, void *value);

void map_delete(Map *mp, void *key);

void *map_get(Map *mp, void *key);

void map_free(Map *mp);

MapIterator *create_map_iterator(Map *mp);

int map_iterator_has_next(MapIterator *it);

void *map_iterator_next(MapIterator *it);

void free_map_iterator(MapIterator *it);

Input parse_input(char *line);

void free_input(Input *input);

void init_bakery(Bakery *b, unsigned period, unsigned capacity);

void free_bakery(Bakery *b);

Batch *create_batch(char *ingredient);

void free_batch(Batch *batch);

Recipe *create_recipe(const char *name, List ingredients, List quantities);

void free_recipe(Recipe *recipe);

Order *create_order(Recipe *recipe, unsigned quantity, unsigned arrival_time);

void free_order(Order *order);

Packet *create_packet(unsigned expiration_time, unsigned quantity);

void free_packet(Packet *packet);

char *create_string(const char *value);

void free_string(char *value);

void add_recipe(Bakery *b, char *recipe_name, List *ingredients, List *quantities);

void remove_recipe(Bakery *b, char *recipe_name);

void restock(Bakery *b, List *ingredients, List *quantities, List *expiration_times);

void place_order(Bakery *b, char *recipe_name, unsigned quantity);

void process_courier(Bakery *b);

void remove_expired_batches(Bakery *b);

void list_init(List *list, FreeOperation free_op) {
    list->data = malloc(LIST_INIT_CAPACITY * sizeof(void *));
    list->size = 0;
    list->capacity = LIST_INIT_CAPACITY;
    list->free_op = free_op;
}

void list_add_back(List *list, void *data) {
    if (list->size == list->capacity) {
        list->capacity *= 2;
        list->data = realloc(list->data, list->capacity * sizeof(void *));
    }
    list->data[list->size++] = data;
}

void list_add_sorted(List *list, void *data, Sorter cmp) {
    list_add_back(list, data);
    for (unsigned i = list->size - 1; i > 0 && cmp(list->data[i], list->data[i - 1]); i--) {
        void *temp = list->data[i];
        list->data[i] = list->data[i - 1];
        list->data[i - 1] = temp;
    }
}

void list_remove(List *list, void *data) {
    for (unsigned i = 0; i < list->size; i++) {
        if (list->data[i] == data) {
            if (list->free_op != NULL)
                list->free_op(list->data[i]);
            memmove(&list->data[i], &list->data[i + 1], (list->size - i - 1) * sizeof(void *));
            list->size--;
            return;
        }
    }
}

void list_pop_front(List *list) {
    if (list->size == 0) return;
    if (list->free_op != NULL)
        list->free_op(list->data[0]);
    memmove(&list->data[0], &list->data[1], (list->size - 1) * sizeof(void *));
    list->size--;
}

void *list_get(List *list, unsigned index) {
    if (index < list->size)
        return list->data[index];
    return NULL;
}

void free_list(List *list) {
    if (list->free_op != NULL)
        for (unsigned i = 0; i < list->size; i++)
            list->free_op(list->data[i]);
    free(list->data);
    list->data = NULL;
    list->size = 0;
    list->capacity = 0;
}

void list_reset(List *list) {
    list->size = 0;
    list->data = NULL;
}

void map_init(Map *mp, KeyComparator key_comparator, HashFunction hash_func, FreeOperation free_op) {
    mp->count = 0;
    mp->hash_func = hash_func;
    mp->key_cmp = key_comparator;
    mp->free_op = free_op;

    for (int i = 0; i < BUCKET_SIZE; i++)
        mp->array[i] = NULL;
}

void map_insert(Map *mp, void *key, void *value) {
    int bucketIndex = mp->hash_func(key) % BUCKET_SIZE;
    MapNode *newNode = malloc(sizeof(MapNode));
    newNode->key = key;
    newNode->value = value;
    newNode->next = NULL;

    if (mp->array[bucketIndex] == NULL)
        mp->array[bucketIndex] = newNode;
    else {
        newNode->next = mp->array[bucketIndex];
        mp->array[bucketIndex] = newNode;
    }

    mp->count++;
}

void map_delete(Map *mp, void *key) {
    int bucketIndex = mp->hash_func(key) % BUCKET_SIZE;
    MapNode *prevNode = NULL;
    MapNode *currNode = mp->array[bucketIndex];
    while (currNode != NULL) {
        if (mp->key_cmp(key, currNode->key)) {
            if (currNode == mp->array[bucketIndex])
                mp->array[bucketIndex] = currNode->next;
            else
                prevNode->next = currNode->next;
            if (mp->free_op != NULL)
                mp->free_op(currNode->value);
            free(currNode);
            mp->count--;
            break;
        }
        prevNode = currNode;
        currNode = currNode->next;
    }
}

void *map_get(Map *mp, void *key) {
    int bucketIndex = mp->hash_func(key) % BUCKET_SIZE;
    MapNode *bucketHead = mp->array[bucketIndex];
    while (bucketHead != NULL) {
        if (mp->key_cmp(bucketHead->key, key))
            return bucketHead->value;
        bucketHead = bucketHead->next;
    }

    return NULL;
}

void map_free(Map *mp) {
    for (int i = 0; i < BUCKET_SIZE; i++) {
        MapNode *currNode = mp->array[i];
        while (currNode != NULL) {
            MapNode *nextNode = currNode->next;
            if (mp->free_op != NULL)
                mp->free_op(currNode->value);
            free(currNode);
            currNode = nextNode;
        }
    }
}

MapIterator *create_map_iterator(Map *mp) {
    MapIterator *it = malloc(sizeof(MapIterator));
    it->mp = mp;
    it->bucketIndex = 0;
    it->current = mp->array[it->bucketIndex];
    return it;
}

int map_iterator_has_next(MapIterator *it) {
    if (it->mp->count == 0) return 0;
    while (it->bucketIndex < BUCKET_SIZE) {
        if (it->current != NULL)
            return 1;
        it->current = it->mp->array[it->bucketIndex++];
    }
    return 0;
}

void *map_iterator_next(MapIterator *it) {
    if (it->current == NULL)
        return NULL;
    void *value = it->current->value;
    it->current = it->current->next;
    return value;
}

void free_map_iterator(MapIterator *it) {
    free(it);
}

Input parse_input(char *line) {
    Input input;

    input.type = INVALID;
    input.recipe_name = 0;
    input.quantity = 0;

    list_init(&input.ingredients, (FreeOperation) free_string);
    list_init(&input.quantities, NULL);
    list_init(&input.expiration_times, NULL);

    for (int i = strlen(line) - 1; i >= 0; --i) {
        if (line[i] == '\n' || line[i] == '\r' || line[i] == ' ' || line[i] == '\t')
            line[i] = 0;
        else
            break;
    }

    if (strlen(line) == 0) return input;

    char *token = strtok(line, " ");
    if (token == NULL) return input;
    if (strcmp(token, ADD_RECIPE_MSG) == 0) {
        token = strtok(NULL, " ");
        if (token == NULL) return input;
        input.recipe_name = create_string(token);
        while ((token = strtok(NULL, " "))) {
            list_add_back(&input.ingredients, create_string(token));
            token = strtok(NULL, " ");
            if (token == NULL) return input;
            unsigned quantity;
            sscanf(token, "%u", &quantity);
            list_add_back(&input.quantities, (void *)(uintptr_t) quantity);
        }
        input.type = ADD_RECIPE;
    } else if (strcmp(token, REMOVE_RECIPE_MSG) == 0) {
        token = strtok(NULL, " ");
        if (token == NULL) return input;
        input.recipe_name = create_string(token);
        input.type = REMOVE_RECIPE;
    } else if (strcmp(token, RESTOCK_MSG) == 0) {
        while ((token = strtok(NULL, " "))) {
            list_add_back(&input.ingredients, create_string(token));
            token = strtok(NULL, " ");
            if (token == NULL) return input;
            unsigned quantity;
            sscanf(token, "%u", &quantity);
            list_add_back(&input.quantities, (void *)(uintptr_t) quantity);
            token = strtok(NULL, " ");
            if (token == NULL) return input;
            unsigned expiration_time;
            sscanf(token, "%u", &expiration_time);
            list_add_back(&input.expiration_times, (void *)(uintptr_t) expiration_time);
        }
        input.type = RESTOCK;
    } else if (strcmp(token, ORDER_MSG) == 0) {
        token = strtok(NULL, " ");
        if (token == NULL) return input;
        input.recipe_name = create_string(token);
        token = strtok(NULL, " ");
        if (token == NULL) return input;
        sscanf(token, "%u", &input.quantity);
        input.type = ORDER;
    }

    return input;
}

void free_input(Input *input) {
    free(input->recipe_name);
    free_list(&input->ingredients);
    free_list(&input->quantities);
    free_list(&input->expiration_times);
}

int string_cmp(char *a, char *b) {
    return strcmp(a, b) == 0;
}

int ptr_cmp(void *a, void *b) {
    return a == b;
}

unsigned long long int string_hash(char *str) {
    unsigned long long int hash = 5381;
    int c;
    while ((c = *str++))
        hash = (hash << 5) + hash + c;
    return hash;
}

void init_bakery(Bakery *b, unsigned period, unsigned capacity) {
    b->current_time = 0;

    map_init(&b->recipes, (KeyComparator) string_cmp, (HashFunction) string_hash, (FreeOperation) free_recipe);
    list_init(&b->pending_orders, (FreeOperation) free_order);
    list_init(&b->queued_orders, (FreeOperation) free_order);
    map_init(&b->batches, (KeyComparator) string_cmp, (HashFunction) string_hash, (FreeOperation) free_batch);

    b->courier.period = period;
    b->courier.capacity = capacity;
    b->courier.next_arrival_time = period;

    b->next_expiry_check = 0;
}

void free_bakery(Bakery *b) {
    map_free(&b->recipes);
    free_list(&b->pending_orders);
    free_list(&b->queued_orders);
    map_free(&b->batches);
}

Batch *create_batch(char *ingredient) {
    Batch *batch = malloc(sizeof(Batch));
    batch->ingredient = create_string(ingredient);
    list_init(&batch->packets, (FreeOperation) free_packet);
    batch->total_quantity = 0;
    return batch;
}

void free_batch(Batch *batch) {
    free(batch->ingredient);
    free_list(&batch->packets);
    free(batch);
}

Recipe *create_recipe(const char *name, List ingredients, List quantities) {
    Recipe *recipe = malloc(sizeof(Recipe));
    recipe->name = create_string(name);
    recipe->ingredient_batches = ingredients;
    recipe->ingredient_quantities = quantities;

    return recipe;
}

void free_recipe(Recipe *recipe) {
    free(recipe->name);
    free_list(&recipe->ingredient_quantities);
    free_list(&recipe->ingredient_batches);
    free(recipe);
}

Order *create_order(Recipe *recipe, unsigned quantity, unsigned arrival_time) {
    Order *order = malloc(sizeof(Order));
    order->recipe = recipe;
    order->quantity = quantity;
    order->arrival_time = arrival_time;
    order->weight = 0;
    order->missing_batch = NULL;
    order->missing_quantity = 0;
    return order;
}

void free_order(Order *order) {
    free(order);
}

Packet *create_packet(unsigned expiration_time, unsigned quantity) {
    Packet *packet = malloc(sizeof(Packet));
    packet->expiration_time = expiration_time;
    packet->quantity = quantity;
    return packet;
}

void free_packet(Packet *packet) {
    free(packet);
}

char *create_string(const char *value) {
    char *str = malloc(strlen(value) + 1);
    strcpy(str, value);
    return str;
}

void free_string(char *value) {
    free(value);
}

int prepare_order(Bakery *b, Order *order) {
    if (order->missing_batch && order->missing_batch->total_quantity < order->missing_quantity)
        return 0;

    Recipe *recipe = order->recipe;

    for (unsigned i = 0; i < recipe->ingredient_batches.size; i++) {
        unsigned quantity = (uintptr_t) list_get(&recipe->ingredient_quantities, i);
        Batch *batch = list_get(&recipe->ingredient_batches, i);

        if (!batch->total_quantity || quantity * order->quantity > batch->total_quantity) {
            order->missing_batch = batch;
            order->missing_quantity = quantity * order->quantity;

            return 0;
        }
    }

    unsigned weight = 0;
    for (unsigned i = 0; i < recipe->ingredient_batches.size; i++) {
        Batch *batch = list_get(&recipe->ingredient_batches, i);
        unsigned quantity = (uintptr_t) list_get(&recipe->ingredient_quantities, i);

        unsigned required_quantity = quantity * order->quantity;
        weight += required_quantity;

        for (unsigned j = 0; j < batch->packets.size; j++) {
            Packet *packet = list_get(&batch->packets, j);

            if (packet->expiration_time <= b->current_time) {
                batch->total_quantity -= packet->quantity;
                list_pop_front(&batch->packets);
                j--;
                continue;
            }

            if (required_quantity < packet->quantity) {
                packet->quantity -= required_quantity;
                batch->total_quantity -= required_quantity;
                break;
            }

            required_quantity -= packet->quantity;
            batch->total_quantity -= packet->quantity;

            list_pop_front(&batch->packets);
            j--;

            if (required_quantity == 0)
                break;
        }
    }

    order->weight = weight;
    return 1;
}

void add_recipe(Bakery *b, char *recipe_name, List *ingredients, List *quantities) {
    if (map_get(&b->recipes, recipe_name)) {
        fprintf(stdout, IGNORED_MSG);
        return;
    }

    List ingredient_batches;
    list_init(&ingredient_batches, NULL);

    for (unsigned i = 0; i < ingredients->size; i++) {
        char *ingredient = list_get(ingredients, i);
        Batch *batch = map_get(&b->batches, ingredient);
        if (batch == NULL) {
            batch = create_batch(ingredient);
            map_insert(&b->batches, batch->ingredient, batch);
        }

        list_add_back(&ingredient_batches, batch);
    }

    Recipe *recipe = create_recipe(recipe_name, ingredient_batches, *quantities);
    map_insert(&b->recipes, recipe->name, recipe);

    list_reset(&ingredient_batches);
    list_reset(quantities);

    free_list(&ingredient_batches);

    fprintf(stdout, ADDED_MSG);
}

void remove_recipe(Bakery *b, char *recipe_name) {
    Recipe *recipe = map_get(&b->recipes, recipe_name);
    if (!recipe) {
        fprintf(stdout, NOT_PRESENT_MSG);
        return;
    }

    for (unsigned i = 0; i < b->pending_orders.size; i++) {
        Order *order = list_get(&b->pending_orders, i);
        if (order->recipe == recipe) {
            fprintf(stdout, PENDING_ORDERS_MSG);
            return;
        }
    }

    for (unsigned i = 0; i < b->queued_orders.size; i++) {
        Order *order = list_get(&b->queued_orders, i);
        if (order->recipe == recipe) {
            fprintf(stdout, PENDING_ORDERS_MSG);
            return;
        }
    }

    map_delete(&b->recipes, recipe_name);
    fprintf(stdout, REMOVED_MSG);
}

int order_sorter_arrival(Order *a, Order *b) {
    return a->arrival_time < b->arrival_time;
}

int order_sorter_weight(Order *a, Order *b) {
    if (a->weight == b->weight)
        return a->arrival_time < b->arrival_time;
    return a->weight > b->weight;
}

int packet_sorter(Packet *a, Packet *b) {
    return a->expiration_time < b->expiration_time;
}

unsigned long long int ptr_hash(void *ptr) {
    return (unsigned long long int) ptr;
}

void restock(Bakery *b, List *ingredients, List *quantities, List *expiration_times) {
    for (unsigned i = 0; i < ingredients->size; i++) {
        char *ingredient = list_get(ingredients, i);
        unsigned quantity = (uintptr_t) list_get(quantities, i);
        unsigned expiration_time = (uintptr_t) list_get(expiration_times, i);

        if (expiration_time <= b->current_time)
            continue;

        Packet *packet = create_packet(expiration_time, quantity);
        Batch *batch = map_get(&b->batches, ingredient);
        if (batch) {
            batch->total_quantity += quantity;
            list_add_sorted(&batch->packets, packet, (Sorter) packet_sorter);
        } else {
            batch = create_batch(ingredient);
            batch->total_quantity += quantity;
            list_add_sorted(&batch->packets, packet, (Sorter) packet_sorter);
            map_insert(&b->batches, batch->ingredient, batch);
        }
    }

    remove_expired_batches(b);

    for (unsigned i = 0; i < b->pending_orders.size; i++) {
        Order *order = list_get(&b->pending_orders, i);
        Recipe *recipe = order->recipe;

        if (prepare_order(b, order)) {
            Order *queued_order = create_order(recipe, order->quantity, order->arrival_time);
            queued_order->weight = order->weight;
            list_add_sorted(&b->queued_orders, queued_order, (Sorter) order_sorter_arrival);
            list_remove(&b->pending_orders, order);
            i--;
        } 
    }
    fprintf(stdout, RESTOCKED_MSG);
}

void place_order(Bakery *b, char *recipe_name, unsigned quantity) {
    Recipe *recipe = map_get(&b->recipes, recipe_name);
    if (recipe == NULL) {
        fprintf(stdout, REJECTED_MSG);
        return;
    }

    Order *order = create_order(recipe, quantity, b->current_time);

    remove_expired_batches(b);
    if (prepare_order(b, order))
        list_add_sorted(&b->queued_orders, order, (Sorter) order_sorter_arrival);
    else
        list_add_back(&b->pending_orders, order);

    fprintf(stdout, ACCEPTED_MSG);
}

void process_courier(Bakery *b) {
    if (b->current_time != b->courier.next_arrival_time)
        return;

    b->courier.next_arrival_time += b->courier.period;

    List selected_orders;
    list_init(&selected_orders, NULL);

    unsigned total_weight = 0;
    for (unsigned i = 0; i < b->queued_orders.size; i++) {
        Order *order = list_get(&b->queued_orders, i);
        if (total_weight + order->weight <= b->courier.capacity) {
            total_weight += order->weight;
            list_add_back(&selected_orders, order);
        } else
            break;
    }

    if (selected_orders.size == 0) {
        fprintf(stdout, EMPTY_TRUCK_MSG);
        free_list(&selected_orders);
        return;
    }

    List sorted_orders;
    list_init(&sorted_orders, NULL);

    for (unsigned i = 0; i < selected_orders.size; i++)
        list_add_sorted(&sorted_orders, list_get(&selected_orders, i), (Sorter) order_sorter_weight);

    for (unsigned i = 0; i < sorted_orders.size; i++) {
        Order *order = list_get(&sorted_orders, i);
        fprintf(stdout, "%u %s %u\n", order->arrival_time, order->recipe->name, order->quantity);
        list_remove(&b->queued_orders, order);
    }

    free_list(&sorted_orders);
    free_list(&selected_orders);
}

void remove_expired_batches(Bakery *b) {
    if (b->current_time < b->next_expiry_check)
        return;

    MapIterator *it = create_map_iterator(&b->batches);
    while (map_iterator_has_next(it)) {
        Batch *batch = map_iterator_next(it);

        for (unsigned i = 0; i < batch->packets.size; i++) {
            Packet *packet = list_get(&batch->packets, i);
            if (packet->expiration_time <= b->current_time) {
                batch->total_quantity -= packet->quantity;
                list_pop_front(&batch->packets);
                i--;
            } else {
                if (b->next_expiry_check == b->current_time || packet->expiration_time < b->next_expiry_check)
                    b->next_expiry_check = packet->expiration_time;
                break;
            }
        }
    }
    free_map_iterator(it);
}

int main() {
    char buffer[BUFSIZE];
    char *line = fgets(buffer, BUFSIZE, stdin);
    unsigned periods, capacity;
    sscanf(line, "%u %u", &periods, &capacity);

    Bakery bakery;
    init_bakery(&bakery, periods, capacity);
    while (!feof(stdin)) {
        process_courier(&bakery);
        line = fgets(buffer, BUFSIZE, stdin);
        if (line == NULL) break;
        Input input = parse_input(line);

        switch (input.type) {
            case ADD_RECIPE:
                add_recipe(&bakery, input.recipe_name, &input.ingredients, &input.quantities);\
                break;
            case REMOVE_RECIPE:
                remove_recipe(&bakery, input.recipe_name);
                break;
            case RESTOCK:
                restock(&bakery, &input.ingredients, &input.quantities, &input.expiration_times);
                break;
            case ORDER:
                place_order(&bakery, input.recipe_name, input.quantity);
                break;
            case INVALID:
                fprintf(stderr, INVALID_OP_MSG);
                free_input(&input);
                continue;
        }
        free_input(&input);
        bakery.current_time++;
    }

    free_bakery(&bakery);
}
