
# Integration test

integration:
	nim c -p=. tests/integration.nim
	./tests/integration_server &
	sleep 0.5
	./tests/integration || echo "TEST FAILED"
	killall integration_server


recreate_mysql_db:
	mysql -uroot -e "DROP DATABASE IF EXISTS httpauth_test;"
	mysql -uroot -e "CREATE DATABASE httpauth_test;"

# Database-only tests - httpauth.nim's logic is not tested

build_dbonly_functional_tests:
	nim c -p=. tests/sql_backend_functional.nim

dbonly_sqlite_functional:
	./tests/sql_backend_functional sqlite:///tmp/httpauth_test.sqlite3

dbonly_mysql_functional:
	./tests/sql_backend_functional mysql://root@localhost/httpauth_test

dbonly_functional: build_dbonly_functional_tests dbonly_sqlite_functional dbonly_mysql_functional


# Functional tests
# The libraries for etcd, MongoDB and Redis are required

build_functional_tests:
	nim c -p=. -d:mock_send_email -d:ssl -d:etcd -d:mongodb -d:redis tests/functional.nim

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

# CircleCI does not provide some databases
circleci: build_functional_tests sqlite_functional recreate_mysql_db mysql_functional mongodb_functional

start_databases:
	sudo systemctl start etcd.service
	sudo systemctl start mongodb.service
	sudo systemctl start mysql.service
	sudo systemctl start redis-server.service

stop_databases:
	sudo systemctl stop etcd.service
	sudo systemctl stop mongodb.service
	sudo systemctl stop mysql.service
	sudo systemctl stop redis-server.service
