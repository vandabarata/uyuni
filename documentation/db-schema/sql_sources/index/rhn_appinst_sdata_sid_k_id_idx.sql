-- created by Oraschemadoc Thu Jan 20 13:49:47 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE INDEX "SPACEWALK"."RHN_APPINST_SDATA_SID_K_ID_IDX" ON "SPACEWALK"."RHNAPPINSTALLSESSIONDATA" ("SESSION_ID", "KEY", "ID") 
  PCTFREE 10 INITRANS 2 MAXTRANS 255 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT)
  TABLESPACE "USERS" 
 
/
