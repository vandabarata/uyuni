-- created by Oraschemadoc Thu Jan 20 13:57:36 2011
-- visit http://www.yarpen.cz/oraschemadoc/ for more info

  CREATE OR REPLACE TRIGGER "SPACEWALK"."RHN_FLMEMBERS_MOD_TRIG" 
before insert or update on rhnFileListMembers
for each row
begin
	:new.modified := sysdate;
end rhn_flmembers_mod_trig;
ALTER TRIGGER "SPACEWALK"."RHN_FLMEMBERS_MOD_TRIG" ENABLE
 
/
