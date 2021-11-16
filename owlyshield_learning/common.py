
columns = ['app_name', 'gid',
           'total_ops_r', 'total_ops_rn', 'total_ops_w', 'total_ops_c',
           'sum_entropy_weight_r', 'sum_entropy_weight_w',
           'extensions_count_r', 'extensions_count_w',
           'file_ids_c_count', 'file_ids_d_count', 'file_ids_r_count', 'file_ids_rn_count', 'file_ids_w_count',
           'files_paths_u_count', 'pids_count', 'extensions_count_w_doc',
           'extensions_count_w_archives',
           'extensions_count_w_db', 'extensions_count_w_code', 'extensions_count_w_exe',
           'dir_with_files_c_count', 'dir_with_files_u_count', 'exe_exists', 'nb_clusters', 'clusters_max_size',
           ]


keep = [
        'total_ops_r', 'total_ops_rn', 'total_ops_w', 'total_ops_c',
        'sum_entropy_weight_r', 'sum_entropy_weight_w', 'extensions_count_r',
           'extensions_count_w',
           'file_ids_c_count', 'file_ids_d_count', 'file_ids_r_count', 'file_ids_rn_count', 'file_ids_w_count',
           'files_paths_u_count', 'pids_count', 'extensions_count_w_doc',
           'extensions_count_w_archives',
           'extensions_count_w_db', 'extensions_count_w_code', 'extensions_count_w_exe',
           'dir_with_files_c_count', 'dir_with_files_u_count', 'exe_exists', 'nb_clusters', 'clusters_max_size',
           ]

columns_reordered = [
            'app_name', 'gid',
            'total_ops_r', 'total_ops_rn', 'total_ops_w', 'total_ops_c',
            'sum_entropy_weight_r', 'sum_entropy_weight_w',
           'file_ids_c_count', 'file_ids_d_count', 'file_ids_r_count', 'file_ids_rn_count', 'file_ids_w_count',
           'files_paths_u_count',
           'extensions_count_r', 'extensions_count_w', 'extensions_count_w_doc',
           'extensions_count_w_archives',
           'extensions_count_w_db', 'extensions_count_w_code', 'extensions_count_w_exe',
           'dir_with_files_c_count', 'dir_with_files_u_count', 'exe_exists', 'nb_clusters', 'clusters_max_size', 'pids_count',

]

