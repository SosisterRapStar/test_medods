#!/bin/bash



docker exec -it db psql -U user -d db -c "INSERT INTO auth.users (user_id, name) VALUES ('06154de3-0d9b-4675-af4f-0cf2d4831dce', 'test_0');INSERT INTO auth.users (user_id, name) VALUES ('218482e1-e180-48bd-ac53-32310c3f1255', 'test_1');INSERT INTO auth.users (user_id, name) VALUES ('9bb4b3f5-201f-4736-a4bc-f6397dc5a57f', 'test_2');
"
