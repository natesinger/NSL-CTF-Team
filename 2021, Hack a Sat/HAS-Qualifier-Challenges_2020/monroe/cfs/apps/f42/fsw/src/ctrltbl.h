/*
** Purpose: CubeSat Controller Table
**
** Notes:
**   1. Use the Singleton design pattern. A pointer to the table object
**      is passed to the constructor and saved for all other operations.
**      This is a table-specific file so it doesn't need to be re-entrant.
**   2. The table file is a JSON text file.
**
** License:
**   Written by David McComas, licensed under the copyleft GNU
**   General Public License (GPL).
**
** References:
**   1. OpenSatKit Object-based Application Developer's Guide.
**   2. cFS Application Developer's Guide.
**
*/
#ifndef _ctrltbl_
#define _ctrltbl_

/*
** Includes
*/

#include "app_cfg.h"
#include "json.h"

/*
** Macro Definitions
*/

/*
** Event Message IDs
*/

#define CTRLTBL_CREATE_FILE_ERR_EID          (CTRLTBL_BASE_EID + 0)
#define CTRLTBL_LOAD_INDEX_ERR_EID           (CTRLTBL_BASE_EID + 1)
#define CTRLTBL_LOAD_LINE_ERR_EID            (CTRLTBL_BASE_EID + 2)
#define CTRLTBL_CMD_LOAD_TYPE_ERR_EID        (CTRLTBL_BASE_EID + 3)
#define CTRLTBL_CMD_LOAD_PARSE_ERR_EID       (CTRLTBL_BASE_EID + 4)
#define CTRLTBL_CMD_LOAD_OPEN_ERR_EID        (CTRLTBL_BASE_EID + 5)
#define CTRLTBL_CMD_LOAD_REPLACE_ERR_EID     (CTRLTBL_BASE_EID + 6)
#define CTRLTBL_CMD_LOAD_UPDATE_ERR_EID      (CTRLTBL_BASE_EID + 7)
#define CTRLTBL_LOAD_MOI_ERR_EID             (CTRLTBL_BASE_EID + 8)
#define CTRLTBL_LOAD_WHL_TGT_MOM_LIM_ERR_EID (CTRLTBL_BASE_EID + 9)

/*
** Table Structure Objects 
*/

#define  CTRLTBL_OBJ_MOI             0
#define  CTRLTBL_OBJ_PD_GAIN_PARAM   1
#define  CTRLTBL_OBJ_WHL_TGT_MOM_LIM 2
#define  CTRLTBL_OBJ_CNT             3

#define  CTRLTBL_OBJ_MOI_NAME              "moment-of-inertia"
#define  CTRLTBL_OBJ_PD_GAIN_PARAM_NAME    "pd-gain-param"
#define  CTRLTBL_OBJ_WHL_TGT_MOM_LIM_NAME  "whl-tgt-mom-lim"
                                           

/*
** Type Definitions
*/


/******************************************************************************
** Table -  Local table copy used for table loads
** 
*/

typedef struct {

   float x;
   float y;
   float z;

} MomentOfInteria_Struct;

typedef struct {

   float w;
   float z;

} PdGainParam_Struct;

typedef struct {

   float Lower;
   float Upper;

} WhlTgtMomLim_Struct;

typedef struct
{

   MomentOfInteria_Struct  Moi;
   PdGainParam_Struct      PdGainParam;
   WhlTgtMomLim_Struct     WhlTgtMomLim;

} CTRLTBL_Struct;


/*
** Table Owner Callback Functions
*/

/* Return pointer to owner's table data */
typedef const CTRLTBL_Struct* (*CTRLTBL_GetTblPtr)(void);
            
/* Table Owner's function to load all table data */
typedef boolean (*CTRLTBL_LoadTbl)(CTRLTBL_Struct* NewTable); 

/* Table Owner's function to load a single table JSON object/container */
typedef boolean (*CTRLTBL_LoadTblEntry)(uint16 ObjId, void* ObjData);   


typedef struct {

   uint8    LastLoadStatus;
   uint16   AttrErrCnt;
   uint16   ObjLoadCnt;

   CTRLTBL_Struct Data;

   CTRLTBL_GetTblPtr    GetTblPtrFunc;
   CTRLTBL_LoadTbl      LoadTblFunc;
   CTRLTBL_LoadTblEntry LoadTblEntryFunc; 

   JSON_Class Json;
   JSON_Obj   JsonObj[CTRLTBL_OBJ_CNT];
   char       JsonFileBuf[JSON_MAX_FILE_CHAR];   
   jsmntok_t  JsonFileTokens[JSON_MAX_FILE_TOKENS];

} CTRLTBL_Class;


/*
** Exported Functions
*/

/******************************************************************************
** Function: CTRLTBL_Constructor
**
** Initialize the Control Table object.
**
** Notes:
**   1. The table values are not populated. This is done when the table is 
**      registered with the table manager.
*/
void CTRLTBL_Constructor(CTRLTBL_Class* ObjPtr,
                         CTRLTBL_GetTblPtr    GetTblPtrFunc,
                         CTRLTBL_LoadTbl      LoadTblFunc, 
                         CTRLTBL_LoadTblEntry LoadTblEntryFunc);


/******************************************************************************
** Function: CTRLTBL_ResetStatus
**
** Reset counters and status flags to a known reset state.  The behavior of
** the table manager should not be impacted. The intent is to clear counters
** and flags to a known default state for telemetry.
**
*/
void CTRLTBL_ResetStatus(void);


/******************************************************************************
** Function: CTRLTBL_LoadCmd
**
** Command to load the table.
**
** Notes:
**  1. Function signature must match TBLMGR_LoadTblFuncPtr.
**  2. Can assume valid table file name because this is a callback from 
**     the app framework table manager.
**
*/
boolean CTRLTBL_LoadCmd(TBLMGR_Tbl *Tbl, uint8 LoadType, const char* Filename);


/******************************************************************************
** Function: CTRLTBL_DumpCmd
**
** Command to dump the table.
**
** Notes:
**  1. Function signature must match TBLMGR_DumpTblFuncPtr.
**  2. Can assume valid table file name because this is a callback from 
**     the app framework table manager.
**
*/
boolean CTRLTBL_DumpCmd(TBLMGR_Tbl *Tbl, uint8 DumpType, const char* Filename);

#endif /* _ctrltbl_ */
