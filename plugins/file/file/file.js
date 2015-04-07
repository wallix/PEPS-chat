// Block default handlers.
function blockHandler(evt) {
  evt.stopPropagation();
  evt.preventDefault();
}

// Get the content of a file and pass it to the upload callback.
function uploadFile(file, upload) {
  if (window.FileReader) {
  	var reader = new FileReader();
  	reader.onload = function (evt) {
      upload(file.name, file.type, file.size, evt.target.result);
  	};
  	reader.readAsDataURL(file);
  } else {
  	console.log("Uploading "+ file.name);
  	var http = new XMLHttpRequest();
  	var form = new FormData();
  	form.append('file', file);
  	http.open('POST', '/upload');
  	http.send(form);
  }
}

/**
 * @register { string, (-> void), (string, string, int, string -> void), (-> void) -> void }
 */
function hookFileDrop(sel, loading, upload, done) {
  $(sel).on('drop', function (evt) {
    e.stopPropagation();
    e.preventDefault();
    loading();
    var oevt = evt.originalEvent;
    $(oevt.dataTransfer.files).each(
      function (key, file) { uploadFile(file, upload); }
    );
    done();
  }).on('dragenter, dragexit, dragover', blockHandler);
}

/**
 * @register { string, (-> void), (string, string, int, string -> void), (-> void) -> void }
 */
function hookFileUpload(sel, loading, upload, done) {
  $(sel).on('change', function(evt) {
    loading();
    $(evt.target.files).each(
	    function(key, file) { uploadFile(file, upload);
    });
    done();
  });
}
