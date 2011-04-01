-- created by Oraschemadoc Thu Jan 20 13:47:20 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE TABLE "SPACEWALK"."RHNSERVERCUSTOMDATAVALUE" 
   (	"SERVER_ID" NUMBER NOT NULL ENABLE, 
	"KEY_ID" NUMBER NOT NULL ENABLE, 
	"VALUE" VARCHAR2(4000), 
	"CREATED_BY" NUMBER, 
	"LAST_MODIFIED_BY" NUMBER, 
	"CREATED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	"MODIFIED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	 CONSTRAINT "RHN_SCDV_SID_FK" FOREIGN KEY ("SERVER_ID")
	  REFERENCES "SPACEWALK"."RHNSERVER" ("ID") ENABLE, 
	 CONSTRAINT "RHN_SCDV_KID_FK" FOREIGN KEY ("KEY_ID")
	  REFERENCES "SPACEWALK"."RHNCUSTOMDATAKEY" ("ID") ENABLE, 
	 CONSTRAINT "RHN_SCDV_CB_FK" FOREIGN KEY ("CREATED_BY")
	  REFERENCES "SPACEWALK"."WEB_CONTACT" ("ID") ON DELETE SET NULL ENABLE, 
	 CONSTRAINT "RHN_SCDV_LMB_FK" FOREIGN KEY ("LAST_MODIFIED_BY")
	  REFERENCES "SPACEWALK"."WEB_CONTACT" ("ID") ON DELETE SET NULL ENABLE
   ) PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS" ENABLE ROW MOVEMENT 
 
/
