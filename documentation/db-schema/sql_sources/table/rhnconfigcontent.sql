-- created by Oraschemadoc Thu Jan 20 13:45:54 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE TABLE "SPACEWALK"."RHNCONFIGCONTENT" 
   (	"ID" NUMBER NOT NULL ENABLE, 
	"CONTENTS" BLOB, 
	"FILE_SIZE" NUMBER, 
	"CHECKSUM_ID" NUMBER NOT NULL ENABLE, 
	"IS_BINARY" CHAR(1) DEFAULT ('N') NOT NULL ENABLE, 
	"DELIM_START" VARCHAR2(16) NOT NULL ENABLE, 
	"DELIM_END" VARCHAR2(16) NOT NULL ENABLE, 
	"CREATED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	"MODIFIED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	 CONSTRAINT "RHN_CONFCONTENT_ISBIN_CK" CHECK (is_binary in ('Y','N')) ENABLE, 
	 CONSTRAINT "RHN_CONFCONTENT_ID_PK" PRIMARY KEY ("ID")
  USING INDEX PCTFREE 10 INITRANS 2 MAXTRANS 255 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS"  ENABLE, 
	 CONSTRAINT "RHN_CONFCONTENT_CHSUM_FK" FOREIGN KEY ("CHECKSUM_ID")
	  REFERENCES "SPACEWALK"."RHNCHECKSUM" ("ID") ENABLE
   ) PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS" 
 LOB ("CONTENTS") STORE AS (
  TABLESPACE "USERS" ENABLE STORAGE IN ROW CHUNK 8192 PCTVERSION 10
  NOCACHE LOGGING 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)) ENABLE ROW MOVEMENT 
 
/
