import json

class DataBase(object):
    def __init__(self,file_name):
        self.file_name=file_name
        pass
    def load_database(self):
        with open(self.file_name, 'r') as outfile:
            data = json.load(outfile)
        return data

    def write_database(self,data):
        with open(self.file_name, 'w') as outfile:
            json.dump(data, outfile)

class StudyGroup():
    def __init__(self):
        pass
    def create(self,file_name):
        return "./database.json"

class Learning(object):
    def __init__(self,study):
        self.data = study
        pass
    def _foreach(self,m,*argc):
        for d in self.data:
            m(d,*argc)
    def remember(self,uuid):
        def _add(d,uuid):
            if d['id'] == uuid:
                d['priority'] = d['priority'] + 1
        self._foreach(_add,uuid)

    def forget(self,uuid):
        def _dec(d,uuid):
            if d['id'] == uuid:
                d['priority'] = d['priority'] - 1
        self._foreach(_dec,uuid)

if __name__ == "__main__":
    words_list=StudyGroup().create("source.list");
    print(words_list)
    data=DataBase(words_list).load_database()
    print data
    Learning(data).remember('B6804FFC-A42B-4F78-892D-630E12FF5EAF');
    print data
    Learning(data).forget('B6804FFC-A42B-4F78-892D-630E12FF5EAF');
    print data
    DataBase('./result.json').write_database(data)
