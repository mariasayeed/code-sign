/*
 * pkcs11_types.h -- Complete PKCS#11 v2.40 types for the HSM PKCS#11 bridge
 *
 * Hand-rolled to avoid external header dependencies whilst providing the FULL
 * CK_FUNCTION_LIST struct in the correct 68-slot canonical order.
 *
 * Root cause of previous SIGSEGV: the struct was truncated after C_GetTokenInfo
 * (slot 7) with a padding[64] kludge.  CST calls C_OpenSession at slot 13,
 * so any access beyond slot 7 hit padding zeros => NULL function pointer crash.
 */

#ifndef PKCS11_TYPES_H
#define PKCS11_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  define CK_EXPORT __declspec(dllexport)
#  define CK_CALL   __cdecl
#else
#  define CK_EXPORT __attribute__((visibility("default")))
#  define CK_CALL
#endif

/* ---- Basic types --------------------------------------------------------- */
typedef unsigned char      CK_BYTE;
typedef unsigned char      CK_BBOOL;
typedef unsigned long      CK_ULONG;
typedef long               CK_LONG;
typedef CK_ULONG           CK_FLAGS;
typedef CK_ULONG           CK_SLOT_ID;
typedef CK_ULONG           CK_SESSION_HANDLE;
typedef CK_ULONG           CK_OBJECT_HANDLE;
typedef CK_ULONG           CK_MECHANISM_TYPE;
typedef CK_ULONG           CK_ATTRIBUTE_TYPE;
typedef CK_ULONG           CK_OBJECT_CLASS;
typedef CK_ULONG           CK_RV;
typedef CK_ULONG           CK_NOTIFICATION;
typedef CK_ULONG           CK_USER_TYPE;
typedef void *             CK_VOID_PTR;
typedef CK_BYTE *          CK_BYTE_PTR;
typedef CK_ULONG *         CK_ULONG_PTR;
typedef CK_MECHANISM_TYPE* CK_MECHANISM_TYPE_PTR;

#define CK_FALSE  0
#define CK_TRUE   1
#define NULL_PTR  ((void*)0)

/* ---- CK_RV return codes -------------------------------------------------- */
#define CKR_OK                      0x00000000UL
#define CKR_ARGUMENTS_BAD           0x00000007UL
#define CKR_ATTRIBUTE_TYPE_INVALID  0x00000012UL
#define CKR_FUNCTION_FAILED         0x00000006UL
#define CKR_FUNCTION_NOT_SUPPORTED  0x00000054UL
#define CKR_KEY_HANDLE_INVALID      0x00000060UL
#define CKR_MECHANISM_INVALID       0x00000070UL
#define CKR_OBJECT_HANDLE_INVALID   0x00000082UL
#define CKR_SESSION_HANDLE_INVALID  0x000000B3UL
#define CKR_GENERAL_ERROR           0x00000005UL
#define CKR_BUFFER_TOO_SMALL               0x00000150UL
#define CKR_SLOT_ID_INVALID                0x00000003UL
#define CKR_OPERATION_NOT_INITIALIZED      0x00000090UL

/* ---- Flags --------------------------------------------------------------- */
#define CKF_TOKEN_PRESENT        0x00000001UL
#define CKF_REMOVABLE_DEVICE     0x00000002UL
#define CKF_HW_SLOT              0x00000004UL
#define CKF_TOKEN_INITIALIZED    0x00000400UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_SERIAL_SESSION       0x00000004UL
#define CKF_RW_SESSION           0x00000002UL
#define CKF_LOGIN_REQUIRED       0x00000004UL

/* ---- Object classes / attributes ----------------------------------------- */
#define CKO_PUBLIC_KEY   0x00000002UL
#define CKO_PRIVATE_KEY  0x00000003UL
#define CKO_CERTIFICATE  0x00000001UL
#define CKA_CLASS             0x00000000UL
#define CKA_TOKEN             0x00000001UL
#define CKA_PRIVATE           0x00000002UL
#define CKA_LABEL             0x00000003UL
#define CKA_VALUE             0x00000011UL
#define CKA_CERTIFICATE_TYPE  0x00000080UL
#define CKA_KEY_TYPE          0x00000100UL
#define CKA_SIGN              0x00000108UL
#define CKA_ID                0x00000102UL
#define CKA_MODULUS           0x00000120UL
#define CKA_PUBLIC_EXPONENT   0x00000122UL
#define CKA_MODULUS_BITS      0x00000121UL

typedef CK_ULONG CK_KEY_TYPE;
#define CKK_RSA  0x00000000UL

typedef CK_ULONG CK_CERTIFICATE_TYPE;
#define CKC_X_509  0x00000000UL

/* ---- Mechanism types ----------------------------------------------------- */
#define CKM_RSA_PKCS        0x00000001UL
#define CKM_SHA256_RSA_PKCS 0x00000040UL

/* ---- User types ---------------------------------------------------------- */
#define CKU_SO   0UL
#define CKU_USER 1UL

/* ---- Version ------------------------------------------------------------- */
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;

/* ---- Info structures ----------------------------------------------------- */
typedef struct {
    CK_VERSION  cryptokiVersion;
    CK_BYTE     manufacturerID[32];
    CK_FLAGS    flags;
    CK_BYTE     libraryDescription[32];
    CK_VERSION  libraryVersion;
} CK_INFO;
typedef CK_INFO *CK_INFO_PTR;

typedef struct {
    CK_BYTE     slotDescription[64];
    CK_BYTE     manufacturerID[32];
    CK_FLAGS    flags;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

typedef struct {
    CK_BYTE     label[32];
    CK_BYTE     manufacturerID[32];
    CK_BYTE     model[16];
    CK_BYTE     serialNumber[16];
    CK_FLAGS    flags;
    CK_ULONG    ulMaxSessionCount;
    CK_ULONG    ulSessionCount;
    CK_ULONG    ulMaxRwSessionCount;
    CK_ULONG    ulRwSessionCount;
    CK_ULONG    ulMaxPinLen;
    CK_ULONG    ulMinPinLen;
    CK_ULONG    ulTotalPublicMemory;
    CK_ULONG    ulFreePublicMemory;
    CK_ULONG    ulTotalPrivateMemory;
    CK_ULONG    ulFreePrivateMemory;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
    CK_BYTE     utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

typedef struct {
    CK_SLOT_ID  slotID;
    CK_ULONG    state;
    CK_FLAGS    flags;
    CK_ULONG    ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef struct {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR       pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM *CK_MECHANISM_PTR;

typedef struct {
    CK_MECHANISM_TYPE type;
    CK_ULONG          ulMinKeySize;
    CK_ULONG          ulMaxKeySize;
    CK_FLAGS          flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;

/* CK_NOTIFY -- notification callback; always NULL in our use-case */
typedef CK_RV (CK_CALL *CK_NOTIFY)(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR);

/* ---- Forward declaration ------------------------------------------------- */
typedef struct CK_FUNCTION_LIST   CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *        CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST **       CK_FUNCTION_LIST_PTR_PTR;

/* ---- Function pointer typedefs (canonical PKCS#11 v2.40 order) ----------- */
typedef CK_RV (CK_CALL *CK_C_Initialize)(CK_VOID_PTR);
typedef CK_RV (CK_CALL *CK_C_Finalize)(CK_VOID_PTR);
typedef CK_RV (CK_CALL *CK_C_GetInfo)(CK_INFO *);
typedef CK_RV (CK_CALL *CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
typedef CK_RV (CK_CALL *CK_C_GetSlotList)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (CK_CALL *CK_C_GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO *);
typedef CK_RV (CK_CALL *CK_C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO *);
typedef CK_RV (CK_CALL *CK_C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE *, CK_ULONG *);
typedef CK_RV (CK_CALL *CK_C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO *);
typedef CK_RV (CK_CALL *CK_C_InitToken)(CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE *);
typedef CK_RV (CK_CALL *CK_C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_SetPIN)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE *);
typedef CK_RV (CK_CALL *CK_C_CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV (CK_CALL *CK_C_CloseAllSessions)(CK_SLOT_ID);
typedef CK_RV (CK_CALL *CK_C_GetSessionInfo)(CK_SESSION_HANDLE, CK_SESSION_INFO *);
typedef CK_RV (CK_CALL *CK_C_GetOperationState)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_SetOperationState)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_Logout)(CK_SESSION_HANDLE);
typedef CK_RV (CK_CALL *CK_C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (CK_CALL *CK_C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (CK_CALL *CK_C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_GetObjectSize)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *);
typedef CK_RV (CK_CALL *CK_C_FindObjectsFinal)(CK_SESSION_HANDLE);
typedef CK_RV (CK_CALL *CK_C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
typedef CK_RV (CK_CALL *CK_C_Digest)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DigestUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_SignRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_SignRecover)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (CK_CALL *CK_C_VerifyRecover)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (CK_CALL *CK_C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
typedef CK_RV (CK_CALL *CK_C_WrapKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (CK_CALL *CK_C_UnwrapKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (CK_CALL *CK_C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (CK_CALL *CK_C_SeedRandom)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_GenerateRandom)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (CK_CALL *CK_C_GetFunctionStatus)(CK_SESSION_HANDLE);
typedef CK_RV (CK_CALL *CK_C_CancelFunction)(CK_SESSION_HANDLE);
typedef CK_RV (CK_CALL *CK_C_WaitForSlotEvent)(CK_FLAGS, CK_SLOT_ID *, CK_VOID_PTR);

/* ---- Complete CK_FUNCTION_LIST: 68 slots in PKCS#11 v2.40 order --------- */
struct CK_FUNCTION_LIST {
    CK_VERSION               version;
    /* General */
    CK_C_Initialize          C_Initialize;
    CK_C_Finalize            C_Finalize;
    CK_C_GetInfo             C_GetInfo;
    CK_C_GetFunctionList     C_GetFunctionList;
    /* Slot/token */
    CK_C_GetSlotList         C_GetSlotList;
    CK_C_GetSlotInfo         C_GetSlotInfo;
    CK_C_GetTokenInfo        C_GetTokenInfo;
    CK_C_GetMechanismList    C_GetMechanismList;
    CK_C_GetMechanismInfo    C_GetMechanismInfo;
    CK_C_InitToken           C_InitToken;
    CK_C_InitPIN             C_InitPIN;
    CK_C_SetPIN              C_SetPIN;
    /* Session */
    CK_C_OpenSession         C_OpenSession;
    CK_C_CloseSession        C_CloseSession;
    CK_C_CloseAllSessions    C_CloseAllSessions;
    CK_C_GetSessionInfo      C_GetSessionInfo;
    CK_C_GetOperationState   C_GetOperationState;
    CK_C_SetOperationState   C_SetOperationState;
    CK_C_Login               C_Login;
    CK_C_Logout              C_Logout;
    /* Object */
    CK_C_CreateObject        C_CreateObject;
    CK_C_CopyObject          C_CopyObject;
    CK_C_DestroyObject       C_DestroyObject;
    CK_C_GetObjectSize       C_GetObjectSize;
    CK_C_GetAttributeValue   C_GetAttributeValue;
    CK_C_SetAttributeValue   C_SetAttributeValue;
    CK_C_FindObjectsInit     C_FindObjectsInit;
    CK_C_FindObjects         C_FindObjects;
    CK_C_FindObjectsFinal    C_FindObjectsFinal;
    /* Encryption */
    CK_C_EncryptInit         C_EncryptInit;
    CK_C_Encrypt             C_Encrypt;
    CK_C_EncryptUpdate       C_EncryptUpdate;
    CK_C_EncryptFinal        C_EncryptFinal;
    /* Decryption */
    CK_C_DecryptInit         C_DecryptInit;
    CK_C_Decrypt             C_Decrypt;
    CK_C_DecryptUpdate       C_DecryptUpdate;
    CK_C_DecryptFinal        C_DecryptFinal;
    /* Digest */
    CK_C_DigestInit          C_DigestInit;
    CK_C_Digest              C_Digest;
    CK_C_DigestUpdate        C_DigestUpdate;
    CK_C_DigestKey           C_DigestKey;
    CK_C_DigestFinal         C_DigestFinal;
    /* Signing */
    CK_C_SignInit            C_SignInit;
    CK_C_Sign                C_Sign;
    CK_C_SignUpdate          C_SignUpdate;
    CK_C_SignFinal           C_SignFinal;
    CK_C_SignRecoverInit     C_SignRecoverInit;
    CK_C_SignRecover         C_SignRecover;
    /* Verification */
    CK_C_VerifyInit          C_VerifyInit;
    CK_C_Verify              C_Verify;
    CK_C_VerifyUpdate        C_VerifyUpdate;
    CK_C_VerifyFinal         C_VerifyFinal;
    CK_C_VerifyRecoverInit   C_VerifyRecoverInit;
    CK_C_VerifyRecover       C_VerifyRecover;
    /* Combined ops */
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate   C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    /* Key management */
    CK_C_GenerateKey         C_GenerateKey;
    CK_C_GenerateKeyPair     C_GenerateKeyPair;
    CK_C_WrapKey             C_WrapKey;
    CK_C_UnwrapKey           C_UnwrapKey;
    CK_C_DeriveKey           C_DeriveKey;
    /* Random */
    CK_C_SeedRandom          C_SeedRandom;
    CK_C_GenerateRandom      C_GenerateRandom;
    /* Parallel I/O */
    CK_C_GetFunctionStatus   C_GetFunctionStatus;
    CK_C_CancelFunction      C_CancelFunction;
    CK_C_WaitForSlotEvent    C_WaitForSlotEvent;
};

#define CK_INVALID_HANDLE 0UL

#endif /* PKCS11_TYPES_H */
