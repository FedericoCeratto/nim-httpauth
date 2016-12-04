
# Integration test

integration:
	nim c -p=. tests/integration.nim
	./tests/integration_server &
	sleep 0.5
	./tests/integration || echo "TEST FAILED"
	killall integration_server

# Database-only tests

build_db_functional_tests:
	nim c -p=. tests/sql_backend_functional.nim

db_sqlite_functional:
	./tests/sql_backend_functional sqlite:///tmp/httpauth_test.sqlite3

db_mysql_functional:
	./tests/sql_backend_functional mysql://root@localhost/httpauth_test

db_functional: build_db_functional_tests db_sqlite_functional db_mysql_functional

# Functional tests

build_functional_tests:
	nim c -p=. -d:mock_send_email -d:ssl -d:etcd -d:mongodb tests/functional.nim

sqlite_functional:
	./tests/functional sqlite:///tmp/httpauth_test.sqlite3

mysql_functional:
	./tests/functional mysql://root@localhost/httpauth_test

etcd_functional:
	./tests/functional etcd://localhost:2379/httpauth_test

redis_functional:
	./tests/functional redis://localhost:2884/httpauth_test

mongodb_functional:
	./tests/functional mongodb://localhost/httpauth_test

functional: build_functional_tests sqlite_functional mysql_functional etcd_functional mongodb_functional
