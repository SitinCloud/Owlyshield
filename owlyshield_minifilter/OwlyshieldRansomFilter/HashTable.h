#pragma once
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64 // Non paged pool NX

// Hashnode class
struct HashNode
{
    LIST_ENTRY entry;
    HANDLE value;
    ULONGLONG key;

    // Constructor of hashnode
    HashNode(ULONGLONG skey, HANDLE svalue)
    {
        InitializeListHead(&entry);
        value = svalue;
        key = skey;
    }

    void *operator new(size_t size)
    {
        void *ptr = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'RW');
        if (ptr != 0)
        {
            memset(ptr, 0, size);
        }
        return ptr;
    }

    void operator delete(void *ptr)
    {
        ExFreePoolWithTag(ptr, 'RW');
    }
    // fixme needs new and delete operator
};

// Our own Hashmap class - implemented as array of list entries
class HashMap
{
    // hash element array
    PLIST_ENTRY arr[100];

    ULONGLONG capacity;
    // current size
    ULONGLONG size;
    // dummy node

  public:
    HashMap()
    {
        // Initial capacity of hash array
        capacity = 100;
        size = 0;

        // Initialise all elements of array as NULL
        for (ULONGLONG i = 0; i < capacity; i++)
        {
            arr[i] = new LIST_ENTRY;
            InitializeListHead(arr[i]);
        }
    }

    ~HashMap()
    {
        for (ULONGLONG i = 0; i < capacity; i++)
        {
            delete (arr[i]);
        }
    }

    // This implements hash function to find index for a key
    ULONGLONG hashCode(ULONGLONG key)
    {
        return key % capacity;
    }

    // Function to add key value pair
    HANDLE insertNode(ULONGLONG key, HANDLE value)
    {
        ULONGLONG hashIndex = hashCode(key);

        PLIST_ENTRY head = arr[hashIndex];
        PLIST_ENTRY iterator = head->Flink;
        while (iterator != head)
        { // update
            HashNode *pClass;
            //
            // Do some processing.
            //
            pClass = (HashNode *)CONTAINING_RECORD(iterator, HashNode, entry);
            if (pClass->key == key)
            {
                HANDLE val = pClass->value;
                pClass->value = value;
                return val;
            }
            iterator = iterator->Flink;
        }
        // insert, no key found
        HashNode *temp = new HashNode(key, value);
        InsertHeadList(head, &(temp->entry));
        size++;
        return value;
    }

    // Function to delete a key value pair
    HANDLE deleteNode(ULONGLONG key)
    {
        ULONGLONG hashIndex = hashCode(key);

        PLIST_ENTRY head = arr[hashIndex];
        PLIST_ENTRY iterator = head->Flink;
        while (iterator != head)
        {
            HashNode *pClass;
            //
            // Do some processing.
            //
            pClass = (HashNode *)CONTAINING_RECORD(iterator, HashNode, entry);
            if (pClass->key == key)
            {
                RemoveEntryList(iterator);
                HANDLE value = pClass->value;
                size--;
                delete pClass;
                return value;
            }
            iterator = iterator->Flink;
        }

        // If not found return null
        return NULL;
    }

    // Function to search the value for a given key
    HANDLE get(ULONGLONG key)
    {
        ULONGLONG hashIndex = hashCode(key);
        PLIST_ENTRY head = arr[hashIndex];
        PLIST_ENTRY iterator = head->Flink;
        while (iterator != head)
        {
            HashNode *pClass;
            //
            // Do some processing.
            //
            pClass = (HashNode *)CONTAINING_RECORD(iterator, HashNode, entry);
            if (pClass->key == key)
            {
                return pClass->value;
            }
            iterator = iterator->Flink;
        }

        // If not found return null
        return NULL;
    }

    // Return current size
    ULONGLONG sizeofMap()
    {
        return size;
    }

    // Return true if size is 0
    bool isEmpty()
    {
        return size == 0;
    }
};