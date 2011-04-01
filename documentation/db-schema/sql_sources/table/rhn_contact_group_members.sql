-- created by Oraschemadoc Thu Jan 20 13:48:28 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE TABLE "SPACEWALK"."RHN_CONTACT_GROUP_MEMBERS" 
   (	"CONTACT_GROUP_ID" NUMBER NOT NULL ENABLE, 
	"ORDER_NUMBER" NUMBER NOT NULL ENABLE, 
	"MEMBER_CONTACT_METHOD_ID" NUMBER, 
	"MEMBER_CONTACT_GROUP_ID" NUMBER, 
	"LAST_UPDATE_USER" VARCHAR2(40) NOT NULL ENABLE, 
	"LAST_UPDATE_DATE" DATE NOT NULL ENABLE, 
	 CONSTRAINT "RHN_CNTGM_CGID_ORDER_PK" PRIMARY KEY ("CONTACT_GROUP_ID", "ORDER_NUMBER")
  USING INDEX PCTFREE 10 INITRANS 2 MAXTRANS 255 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS"  ENABLE, 
	 CONSTRAINT "RHN_CNTGM_CGID_FK" FOREIGN KEY ("CONTACT_GROUP_ID")
	  REFERENCES "SPACEWALK"."RHN_CONTACT_GROUPS" ("RECID") ON DELETE CASCADE ENABLE, 
	 CONSTRAINT "RHN_CNTGM_MCMID_FK" FOREIGN KEY ("MEMBER_CONTACT_METHOD_ID")
	  REFERENCES "SPACEWALK"."RHN_CONTACT_METHODS" ("RECID") ON DELETE CASCADE ENABLE, 
	 CONSTRAINT "RHN_CNTGM_MCGID_FK" FOREIGN KEY ("MEMBER_CONTACT_GROUP_ID")
	  REFERENCES "SPACEWALK"."RHN_CONTACT_GROUPS" ("RECID") ON DELETE CASCADE ENABLE
   ) PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS" ENABLE ROW MOVEMENT 
 
/
