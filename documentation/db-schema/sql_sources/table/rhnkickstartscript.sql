-- created by Oraschemadoc Thu Jan 20 13:46:35 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE TABLE "SPACEWALK"."RHNKICKSTARTSCRIPT" 
   (	"ID" NUMBER NOT NULL ENABLE, 
	"KICKSTART_ID" NUMBER NOT NULL ENABLE, 
	"POSITION" NUMBER NOT NULL ENABLE, 
	"SCRIPT_TYPE" VARCHAR2(4) NOT NULL ENABLE, 
	"CHROOT" CHAR(1) DEFAULT ('Y') NOT NULL ENABLE, 
	"RAW_SCRIPT" CHAR(1) DEFAULT ('Y') NOT NULL ENABLE, 
	"INTERPRETER" VARCHAR2(80), 
	"DATA" BLOB, 
	"CREATED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	"MODIFIED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	 CONSTRAINT "RHN_KSSCRIPT_ST_CK" CHECK (script_type in ('pre','post')) ENABLE, 
	 CONSTRAINT "RHN_KSSCRIPT_CHROOT_CK" CHECK (chroot in ('Y','N')) ENABLE, 
	 CONSTRAINT "RHN_KSSCRIPT_RAWSCRIPT_CK" CHECK (raw_script in ('Y','N')) ENABLE, 
	 CONSTRAINT "RHN_KSSCRIPT_ID_PK" PRIMARY KEY ("ID")
  USING INDEX PCTFREE 10 INITRANS 2 MAXTRANS 255 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS"  ENABLE, 
	 CONSTRAINT "RHN_KSSCRIPT_KSID_POS_UQ" UNIQUE ("KICKSTART_ID", "POSITION")
  USING INDEX PCTFREE 10 INITRANS 2 MAXTRANS 255 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS"  ENABLE, 
	 CONSTRAINT "RHN_KSSCRIPT_KSID_FK" FOREIGN KEY ("KICKSTART_ID")
	  REFERENCES "SPACEWALK"."RHNKSDATA" ("ID") ON DELETE CASCADE ENABLE
   ) PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS" 
 LOB ("DATA") STORE AS (
  TABLESPACE "USERS" ENABLE STORAGE IN ROW CHUNK 8192 PCTVERSION 10
  NOCACHE LOGGING 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)) ENABLE ROW MOVEMENT 
 
/
