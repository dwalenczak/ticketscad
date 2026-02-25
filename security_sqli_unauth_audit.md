# Unauthenticated SQL Injection Audit (Narrowed)

This report narrows to likely externally reachable scripts without an in-file auth gate and flags SQL statements that appear to use client-controlled values with no/weak SQL sanitization.

## Heuristics
- Unauthenticated in-file: no `do_login(...)` call and no `login.inc.php` include.
- SQL sink: query variable assigned SQL text and executed by `mysql_query`/`mysqli_query` nearby.
- Taint source: direct assignment from `$_GET`, `$_POST`, `$_REQUEST`, or `$_COOKIE`.
- Sanitization classes:
  - **STRONG (filtered out):** `intval`, `floatval`, `quote_smart`, `smart_quote`, `mysql_real_escape_string`, `mysqli_real_escape_string`.
  - **WEAK (reported as MED):** `addslashes`, `strip_tags`, `htmlspecialchars`, `htmlentities`, `trim`.

## Summary
- Flagged files: **76**

### `add_facnote.php`
- `query` SQL block lines **69-121** — risk: **HIGH**
  - HIGH: $ticket_id from client input (TAINT) assigned at line 66: `$_GET['ticket_id']`
- `query` SQL block lines **148-164** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `add_note.php`
- `query` SQL block lines **96-127** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
  - HIGH: $the_in_str from client input (TAINT) assigned at line 122: `($_POST['frm_add_to']=="0")? $row['description'] : $row['comments'] `

### `ajax/action_form.php`
- `query` SQL block lines **25-32** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ajax/del_message.php`
- `query` SQL block lines **11-53** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 8: `(isset($_GET['id'])) ? clean_string($_GET['id']) : NULL`

### `ajax/file_list.php`
- `query` SQL block lines **30-35** — risk: **HIGH**
  - HIGH: $portaluser from client input (TAINT) assigned at line 15: `(isset($_GET['portaluser'])) ? $_GET['portaluser'] : 0`

### `ajax/form_post.php`
- `query` SQL block lines **23-31** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
  - HIGH: $the_in_str from client input (TAINT) assigned at line 29: `($_POST['frm_add_to']=="0")? $row['description'] : $row['comments'] `
- `query` SQL block lines **51-57** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
  - HIGH: $frm_asof from client input (TAINT) assigned at line 170: `"$_POST[frm_year_asof]-$_POST[frm_month_asof]-$_POST[frm_day_asof] $_POST[frm_hour_asof]:$_POST[frm_minute_asof]:00$frm_meridiem_asof"`
- `query` SQL block lines **62-69** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
  - HIGH: $frm_asof from client input (TAINT) assigned at line 170: `"$_POST[frm_year_asof]-$_POST[frm_month_asof]-$_POST[frm_day_asof] $_POST[frm_hour_asof]:$_POST[frm_minute_asof]:00$frm_meridiem_asof"`
- `query` SQL block lines **118-124** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
  - HIGH: $frm_asof from client input (TAINT) assigned at line 170: `"$_POST[frm_year_asof]-$_POST[frm_month_asof]-$_POST[frm_day_asof] $_POST[frm_hour_asof]:$_POST[frm_minute_asof]:00$frm_meridiem_asof"`
- `query` SQL block lines **140-159** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **182-193** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **197-219** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **222-234** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ajax/fs_facs_popup.php`
- `query` SQL block lines **19-54** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 12: `$_GET['id']`

### `ajax/full_screen_incidents.php`
- `query` SQL block lines **173-178** — risk: **HIGH**
  - HIGH: $sort_by_field from client input (TAINT) assigned at line 17: `(!(array_key_exists('sortbyfield', $_GET))) ? "" : $_GET['sortbyfield']`
  - HIGH: $sort_value from client input (TAINT) assigned at line 18: `(!(array_key_exists('sort_value', $_GET))) ? "" : $_GET['sort_value']`

### `ajax/fullsit_incidents.php`
- `query` SQL block lines **169-174** — risk: **HIGH**
  - HIGH: $sort_by_field from client input (TAINT) assigned at line 17: `(!(array_key_exists('sortbyfield', $_GET))) ? "" : $_GET['sortbyfield']`
  - HIGH: $sort_value from client input (TAINT) assigned at line 18: `(!(array_key_exists('sort_value', $_GET))) ? "" : $_GET['sort_value']`

### `ajax/get_fields.php`
- `query` SQL block lines **33-44** — risk: **HIGH**
  - HIGH: $table from client input (TAINT) assigned at line 5: `$_GET['table']`

### `ajax/get_status_control_new.php`
- `query` SQL block lines **13-19** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 9: `$_GET['responder_id']`

### `ajax/get_unit_assignments.php`
- `query` SQL block lines **11-22** — risk: **HIGH**
  - HIGH: $resp_id from client input (TAINT) assigned at line 8: `$_GET['unit']`

### `ajax/list_files.php`
- `query` SQL block lines **57-62** — risk: **HIGH**
  - HIGH: $portaluser from client input (TAINT) assigned at line 16: `(isset($_GET['portaluser'])) ? $_GET['portaluser'] : 0`

### `ajax/list_waste_messages.php`
- `query` SQL block lines **61-71** — risk: **HIGH**
  - HIGH: $where from client input (TAINT) assigned at line 41: `"WHERE `resp_id` = '" . $_GET['responder_id'] . "'"`

### `ajax/mdb_reports.php`
- `query` SQL block lines **113-117** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`
- `query1` SQL block lines **178-181** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`
- `query1` SQL block lines **209-211** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`
- `query1` SQL block lines **237-239** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`
- `query1` SQL block lines **265-267** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`
- `query1` SQL block lines **303-305** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`
- `query1` SQL block lines **334-337** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`
- `query1` SQL block lines **373-376** — risk: **HIGH**
  - HIGH: $member from client input (TAINT) assigned at line 98: `(array_key_exists('member', $_GET)) ? $_GET['member'] : 0`

### `ajax/mi_tic_list.php`
- `query` SQL block lines **166-171** — risk: **HIGH**
  - HIGH: $sort_by_field from client input (TAINT) assigned at line 17: `(!(array_key_exists('sortbyfield', $_GET))) ? "" : $_GET['sortbyfield']`
  - HIGH: $sort_value from client input (TAINT) assigned at line 18: `(!(array_key_exists('sort_value', $_GET))) ? "" : $_GET['sort_value']`

### `ajax/mob_messagelist.php`
- `query` SQL block lines **42-60** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ajax/patient_form.php`
- `query` SQL block lines **56-83** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **110-114** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **307-312** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ajax/reports.php`
- `query` SQL block lines **239-256** — risk: **HIGH**
  - HIGH: $which_unit from client input (TAINT) assigned at line 760: `((!isset($_POST['frm_resp_sel']) || ($_POST['frm_resp_sel']==0)))? "" : " AND `responder_id` = " .$_POST['frm_resp_sel']`

### `ajax/resp_popup.php`
- `query` SQL block lines **16-60** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 11: `$_GET['id']`
- `query` SQL block lines **92-161** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 11: `$_GET['id']`

### `ajax/responder_infowindows.php`
- `query` SQL block lines **77-93** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ajax/restore_message.php`
- `query` SQL block lines **11-53** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 8: `(isset($_GET['id'])) ? clean_string($_GET['id']) : NULL`

### `ajax/sit_incidents.php`
- `query` SQL block lines **167-172** — risk: **HIGH**
  - HIGH: $sort_by_field from client input (TAINT) assigned at line 17: `(!(array_key_exists('sortbyfield', $_GET))) ? "" : $_GET['sortbyfield']`
  - HIGH: $sort_value from client input (TAINT) assigned at line 18: `(!(array_key_exists('sort_value', $_GET))) ? "" : $_GET['sort_value']`

### `ajax/update_assigns.php`
- `query` SQL block lines **56-57** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ajax/update_responder_location.php`
- `query` SQL block lines **17-22** — risk: **HIGH**
  - HIGH: $fac_id from client input (TAINT) assigned at line 14: `$_GET['fac_id']`
  - HIGH: $resp_id from client input (TAINT) assigned at line 15: `$_GET['resp_id']`
- `query` SQL block lines **41-49** — risk: **HIGH**
  - HIGH: $new_status from client input (TAINT) assigned at line 16: `$_GET['status']`

### `ajax/view_event.php`
- `query` SQL block lines **14-16** — risk: **HIGH**
  - HIGH: $ev_id from client input (TAINT) assigned at line 10: `$_GET['ev_id']`

### `ajax/view_training_package.php`
- `query` SQL block lines **14-16** — risk: **HIGH**
  - HIGH: $tp_id from client input (TAINT) assigned at line 10: `$_GET['tp_id']`

### `ajax/view_vehicle_details.php`
- `query` SQL block lines **14-33** — risk: **HIGH**
  - HIGH: $veh_id from client input (TAINT) assigned at line 10: `$_GET['veh_id']`

### `ajax/wb_restore.php`
- `query` SQL block lines **233-252** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `assign_del.php`
- `query` SQL block lines **20-28** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `assign_res.php`
- `query` SQL block lines **22-29** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `assigns_t.php`
- `query` SQL block lines **62-63** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `auto_disp_status.php`
- `query` SQL block lines **41-62** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `auto_status.php`
- `query` SQL block lines **43-63** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `board.php`
- `query` SQL block lines **2375-2379** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **2395-2409** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `chat_invite.php`
- `query` SQL block lines **12-17** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `close_in.php`
- `query` SQL block lines **241-265** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `db_loader.php`
- `query` SQL block lines **678-687** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **782-809** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **825-828** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `do_fac_mail.php`
- `query` SQL block lines **99-100** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `email_lists.php`
- `query` SQL block lines **52-54** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **58-62** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **71-76** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **264-283** — risk: **MED**
  - MED: $id from client input (WEAK) assigned at line 14: `(isset($_GET['id'])) ? strip_tags($_GET['id']) : 0 `

### `faccategories.php`
- `query` SQL block lines **92-99** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **127-133** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `file_upload.php`
- `query_insert` SQL block lines **261-266** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics202.php`
- `query` SQL block lines **398-469** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **489-496** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **635-646** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **663-666** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **679-682** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **696-699** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics205.php`
- `query` SQL block lines **408-474** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **494-501** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **640-651** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **668-671** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **684-687** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **701-704** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics205a.php`
- `query` SQL block lines **350-421** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **441-448** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **587-598** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **615-618** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **631-634** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **648-651** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics206.php`
- `query` SQL block lines **581-651** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **671-678** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **816-827** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **844-847** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **860-863** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **877-880** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics213.php`
- `query` SQL block lines **329-396** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **416-423** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **562-572** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **588-591** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **604-607** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **621-624** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics213rr.php`
- `query` SQL block lines **478-544** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **564-571** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **710-721** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **738-741** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **754-757** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **771-774** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics214.php`
- `query` SQL block lines **356-423** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **443-450** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **589-600** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **617-620** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **633-636** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **650-653** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics214a.php`
- `query` SQL block lines **369-436** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **456-463** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **602-613** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **630-633** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **646-649** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **663-666** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `ics/ics221.php`
- `query` SQL block lines **562-630** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **650-657** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **796-807** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **824-827** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **840-843** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **857-860** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `install.php`
- `query` SQL block lines **1136-1137** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
  - HIGH: $query from client input (TAINT) assigned at line 1136: `"@mysql_connect({$_POST['frm_db_host']}, {$_POST['frm_db_user']}, {$_POST['frm_db_password']})"`

### `message.php`
- `query` SQL block lines **389-392** — risk: **MED**
  - MED: $uid from client input (WEAK) assigned at line 376: `strip_tags($_GET['id'])`

### `nearby.php`
- `query` SQL block lines **11-20** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `os_map.php`
- `query` SQL block lines **67-92** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 30: `$_GET['id']`
- `query` SQL block lines **121-133** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 30: `$_GET['id']`

### `os_watch.php`
- `query` SQL block lines **295-344** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **422-426** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `portal/ajax/cancel_request.php`
- `query` SQL block lines **34-54** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `portal/ajax/decline.php`
- `query` SQL block lines **31-42** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `portal/ajax/insert_request.php`
- `query` SQL block lines **75-136** — risk: **HIGH**
  - HIGH: $lat from client input (TAINT) assigned at line 61: `($_GET['frm_lat'] != "") ? $_GET['frm_lat'] : '0'`
  - HIGH: $lng from client input (TAINT) assigned at line 62: `($_GET['frm_lng'] != "") ? $_GET['frm_lng'] : '0'`
  - HIGH: $origFac from client input (TAINT) assigned at line 73: `($_GET['frm_orig_fac'] != "") ? $_GET['frm_orig_fac'] : '0'`
  - HIGH: $recFac from client input (TAINT) assigned at line 74: `($_GET['frm_rec_fac'] != "") ? $_GET['frm_rec_fac'] : '0'`
  - HIGH: $request_date from client input (TAINT) assigned at line 64: `$_GET['frm_request_date']`

### `portal/ajax/insert_ticket.php`
- `query` SQL block lines **48-53** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **138-157** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `portal/ajax/insert_ticket_tentative.php`
- `query` SQL block lines **48-53** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction
- `query` SQL block lines **136-155** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `portal/ajax/list_requests.php`
- `query` SQL block lines **59-108** — risk: **MED**
  - MED: $where from client input (WEAK) assigned at line 49: `((!empty($_GET)) && (isset($_GET['id']))) ? "WHERE `requester` = " . strip_tags($_GET['id']): ""`

### `portal/ajax/list_requests_admin.php`
- `query` SQL block lines **50-99** — risk: **MED**
  - MED: $where from client input (WEAK) assigned at line 42: `((!empty($_GET)) && (isset($_GET['id']))) ? "WHERE `requester` = " . strip_tags($_GET['id']): ""`

### `quick_start.php`
- `query` SQL block lines **388-391** — risk: **HIGH**
  - HIGH: $inc_type from client input (TAINT) assigned at line 384: `substr($_POST['frm_name'][$i], 0, 20)`
- `query` SQL block lines **403-406** — risk: **HIGH**
  - HIGH: $resp_type from client input (TAINT) assigned at line 400: `substr($_POST['frm_rtype_name'][$i], 0, 16)`

### `rec_fac_t.php`
- `query` SQL block lines **17-21** — risk: **HIGH**
  - HIGH: $tick_id from client input (TAINT) assigned at line 13: `$_POST['tick_id']`
- `query` SQL block lines **24-27** — risk: **HIGH**
  - HIGH: $assign_id from client input (TAINT) assigned at line 14: `$_POST['frm_id']`

### `rm/ajax/chat_invite.php`
- `query` SQL block lines **11-16** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `rm/ajax/get_recfac.php`
- `query` SQL block lines **8-18** — risk: **HIGH**
  - HIGH: $tick_id from client input (TAINT) assigned at line 6: `$_GET['ticket_id']`

### `rm/ajax/ticket_markers.php`
- `query` SQL block lines **20-21** — risk: **HIGH**
  - HIGH: $the_user from client input (TAINT) assigned at line 13: `$_GET['user_id']`

### `rm/ajax/update_assigns.php`
- `query` SQL block lines **51-52** — risk: **HIGH**
  - HIGH: direct $_GET/$_POST/$_REQUEST/$_COOKIE used inside SQL construction

### `rm/ajax/update_mileage.php`
- `query` SQL block lines **20-21** — risk: **HIGH**
  - HIGH: $assigns_id from client input (TAINT) assigned at line 12: `$_GET['assigns_id']`

### `rm/ajax/update_notes.php`
- `query` SQL block lines **21-24** — risk: **HIGH**
  - HIGH: $ticket_id from client input (TAINT) assigned at line 16: `$_GET['ticket_id']`
- `query` SQL block lines **29-30** — risk: **HIGH**
  - HIGH: $ticket_id from client input (TAINT) assigned at line 16: `$_GET['ticket_id']`

### `rm/unit_popup.php`
- `query` SQL block lines **34-46** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 29: `$_GET['id']`

### `unit_popup.php`
- `query` SQL block lines **34-46** — risk: **HIGH**
  - HIGH: $id from client input (TAINT) assigned at line 29: `$_GET['id']`

### `wp_lkup.php`
- `query` SQL block lines **36-38** — risk: **HIGH**
  - HIGH: $phone from client input (TAINT) assigned at line 20: `(empty($_POST))? "1234560000": $_POST['phone']`

### `wp_lkup_cid.php`
- `query` SQL block lines **41-42** — risk: **HIGH**
  - HIGH: $phone from client input (TAINT) assigned at line 19: `(empty($_POST))? "4108498721": $_POST['phone']`

### `wp_lkup_rev.php`
- `query` SQL block lines **39-40** — risk: **HIGH**
  - HIGH: $phone from client input (TAINT) assigned at line 19: `(empty($_POST))? "4108498721": $_POST['phone']`

