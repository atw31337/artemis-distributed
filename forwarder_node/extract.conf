global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
    ["application/octet-stream"] = "exe",
    ["application/javascript"] = "js",
    ["application/java-archive"] = "jar",
    ["application/x-executable"] = "exe",
    ["application/msword"] = "doc",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
    ["application/x-gzip"] = "gz",
    ["application/bzip2"] = "bz2",
    ["application/x-7z-compressed"] = "7z",
    ["application/zip"] = "zip",
    ["application/x-shockwave-flash"] = "swf",
    ["application/pdf"] = "pdf",
    ["application/x-zip-compressed"] = "zip",
    ["application/x-msdownload"] = "dll",
    ["application/json"] = "json",
} &default ="";

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! meta?$mime_type || meta$mime_type != "application/x-dosexec" && meta$mime_type != "application/octet-stream" && meta$mime_type != "application/javascript"
       && meta$mime_type != "application/java-archive" && meta$mime_type != "application/x-executable"
       && meta$mime_type != "application/msword" && meta$mime_type != "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
       && meta$mime_type != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
       && meta$mime_type != "application/vnd.openxmlformats-officedocument.presentationml.presentation"
       && meta$mime_type != "application/x-gzip" && meta$mime_type != "application/bzip2" && meta$mime_type != "application/x-7z-compressed"
       && meta$mime_type != "application/zip" && meta$mime_type != "application/x-shockwave-flash"
       && meta$mime_type != "application/pdf" && meta$mime_type != "application/x-zip-compressed" && meta$mime_type != "application/x-msdownload"
       && meta$mime_type != "application/json" )
        return;

    local ext = "";

    if ( meta?$mime_type )
        ext = ext_map[meta$mime_type];

    local fname = fmt("/nsm/bro/extracted/%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}
