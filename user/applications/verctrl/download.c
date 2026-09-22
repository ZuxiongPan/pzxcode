#include <stdio.h>
#include <curl/curl.h>
#include "verctrl.h"

struct FileData {
    const char *filename;
    FILE *stream;
};

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct FileData *out = (struct FileData *)stream;
    
    if (out && !out->stream)
    {
        out->stream = fopen(out->filename, "wb");
        if (!out->stream)
        {
            return -1;
        }
    }
    
    return fwrite(ptr, size, nmemb, out->stream);
}

int download_upgrade_file(void)
{
    CURL *curl;
    CURLcode res;
    int ret = 0;
    struct FileData file_data;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    curl = curl_easy_init();
    if (curl)
    {
        inform_to_armd(UPG_DOWNLOADING);
        curl_easy_setopt(curl, CURLOPT_URL, UPGRADE_FILE_PATH);
        
        file_data.filename = DOWNLOAD_FILE_PATH;
        file_data.stream = NULL;
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file_data);
        
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
        
        res = curl_easy_perform(curl);
        
        if (res != CURLE_OK)
        {
            inform_to_armd(UPG_DOWNLOAD_FAILED);
            printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            ret = -1;
        }
        else
        {
            inform_to_armd(UPG_DOWNLOADED);
            printf("Download successful.\n");
            ret = 0;
        }
        
        if (file_data.stream)
        {
            fclose(file_data.stream);
        }
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    
    return ret;
}
