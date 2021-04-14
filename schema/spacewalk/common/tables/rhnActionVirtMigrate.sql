--
-- Copyright (c) 2021 SUSE LLC
--
-- This software is licensed to you under the GNU General Public License,
-- version 2 (GPLv2). There is NO WARRANTY for this software, express or
-- implied, including the implied warranties of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
-- along with this software; if not, see
-- http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
--
-- Red Hat trademarks are not licensed under GPLv2. No permission is
-- granted to use or replicate Red Hat trademarks that are incorporated
-- in this software or its documentation.
--

CREATE TABLE rhnActionVirtMigrate
(
    action_id  NUMERIC NOT NULL
                   CONSTRAINT rhn_virt_guest_migrate_aid_fk
                       REFERENCES rhnAction (id)
                       ON DELETE CASCADE
                   CONSTRAINT rhn_action_virt_guest_migrate_aid_pk
                       PRIMARY KEY,
    uuid       VARCHAR(128) NOT NULL,
    primitive  VARCHAR(128),
    target     VARCHAR(128) NOT NULL
)
;
