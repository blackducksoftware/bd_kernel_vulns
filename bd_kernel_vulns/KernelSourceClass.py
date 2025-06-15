# import global_values


class KernelSource:
    def __init__(self, conf):
        self.file_arr = []
        self.folders = conf.folders
        try:
            with open(conf.kernel_source_file) as klfile:
                lines = klfile.readlines()
        except FileExistsError:
            return

        for line in lines:
            line = line.strip()
            if not self.folders:
                if line.endswith('.c') or line.endswith('.h'):
                    self.file_arr.append(line)
            else:
                self.file_arr.append(line)

    def check_files(self, f_arr):
        for f in f_arr:
            for kf in self.file_arr:
                if not self.folders:
                    if kf.endswith(f):
                        return True
                else:
                    folder = f + '/'
                    if kf.find(folder) != -1:
                        return True
        return False

    def count(self):
        return len(self.file_arr)
