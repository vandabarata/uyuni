-- created by Oraschemadoc Thu Jan 20 13:49:01 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE TABLE "SPACEWALK"."WEB_CUSTOMER_NOTIFICATION" 
   (	"ID" NUMBER NOT NULL ENABLE, 
	"ORG_ID" NUMBER NOT NULL ENABLE, 
	"CONTACT_EMAIL_ADDRESS" VARCHAR2(150) NOT NULL ENABLE, 
	"CREATION_DATE" DATE NOT NULL ENABLE, 
	 CONSTRAINT "WEB_CUST_NOT_ID_PK" PRIMARY KEY ("ID")
  USING INDEX PCTFREE 10 INITRANS 2 MAXTRANS 255 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS"  ENABLE, 
	 CONSTRAINT "WEB_CUST_NOT_OID_FK" FOREIGN KEY ("ORG_ID")
	  REFERENCES "SPACEWALK"."WEB_CUSTOMER" ("ID") ON DELETE CASCADE ENABLE
   ) PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS" ENABLE ROW MOVEMENT 
 
/
