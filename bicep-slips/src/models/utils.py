import sqlite3
import json

class DatabaseDumper():
    table_name = "flows"
    db_path = None

    def __init__(self, db_path: str):
        self.db_path = db_path

    def return_table_as_dicts(self):

        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {self.table_name}")
        rows = cursor.fetchall()
        column_names = [description[0] for description in cursor.description]

        table_as_list_of_dicts = [dict(zip(column_names, row)) for row in rows]

        # Close the database connection
        conn.close()
        return table_as_list_of_dicts
    
    def cleanup_table(self):
        delete_query = f"DELETE FROM {self.table_name};"
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(delete_query)
        conn.close()


    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        return conn

    def convert_db_entry_to_hashmap(self, db_entries: list):
        hashmap = {}
        for entry in db_entries:
            key = entry["uid"]
            value = entry["flow"]
            hashmap[key] = value
        return hashmap