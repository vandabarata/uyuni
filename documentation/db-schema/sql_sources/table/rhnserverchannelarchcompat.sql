-- created by Oraschemadoc Thu Jan 20 13:47:19 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE TABLE "SPACEWALK"."RHNSERVERCHANNELARCHCOMPAT" 
   (	"SERVER_ARCH_ID" NUMBER NOT NULL ENABLE, 
	"CHANNEL_ARCH_ID" NUMBER NOT NULL ENABLE, 
	"CREATED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	"MODIFIED" DATE DEFAULT (sysdate) NOT NULL ENABLE, 
	 CONSTRAINT "RHN_SC_AC_SAID_FK" FOREIGN KEY ("SERVER_ARCH_ID")
	  REFERENCES "SPACEWALK"."RHNSERVERARCH" ("ID") ENABLE, 
	 CONSTRAINT "RHN_SC_AC_CAID_FK" FOREIGN KEY ("CHANNEL_ARCH_ID")
	  REFERENCES "SPACEWALK"."RHNCHANNELARCH" ("ID") ENABLE
   ) PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS" ENABLE ROW MOVEMENT 
 
/
