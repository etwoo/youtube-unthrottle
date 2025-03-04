file(READ seatbelt_policy.scm SEATBELT_POLICY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
	seatbelt_policy.scm
)

string(REPLACE "\n" "\\\\n" SEATBELT_POLICY "${SEATBELT_POLICY}")
string(REPLACE "\\\\" "\\" SEATBELT_POLICY_SCM "${SEATBELT_POLICY}")
configure_file(seatbelt_policy.c.in seatbelt_policy.c ESCAPE_QUOTES)

target_sources(youtube PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}/seatbelt_policy.c
	seatbelt.c
)
