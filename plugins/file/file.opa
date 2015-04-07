package file

/**
 * Plugin inspired by pixlpaste : https://github.com/alokmenghrajani/pixlpaste
 * and http://www.thebuzzmedia.com/html5-drag-and-drop-and-file-api-tutorial/
 * and http://www.deadmarshes.com/Blog/20110413023355.html
 */
module FilePlugin {

  client function hookFileDrop(dom dom, loading, upload, done) {
    %%file.hookFileDrop%%(Dom.to_string(dom), loading, upload, done)
  }

  client function hookFileUpload(dom dom, loading, upload, done) {
    %%file.hookFileUpload%%(Dom.to_string(dom), loading, upload, done)
  }

}
