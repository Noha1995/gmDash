$(document).ready(function () {
    $('.ids-checkall').change(function (e) {
        let form = $(this).closest('form');
        let tbl = $(this).closest('table');
        const status = $(this)[0].checked;

        tbl.find('input.ids-check').each(function (ind, item) {
            item.checked = status;
        });

        const len_checked = tbl.find("input.ids-check:checked").length;
        if (status && len_checked) {
            $('#btn-delete-inbox').removeAttr('disabled');
        } else {
            $('#btn-delete-inbox').attr('disabled', true);
        }
    });

    $('input.ids-check').change(function () {
        let tbl = $(this).closest('table');
        const len = tbl.find("input.ids-check").length;
        const len_checked = tbl.find("input.ids-check:checked").length;
        tbl.find('input.ids-checkall:eq(0)')[0].checked = len == len_checked;
        if (len_checked > 0) {
            $('#btn-delete-inbox').removeAttr('disabled');
        } else {
            $('#btn-delete-inbox').attr('disabled', true);
        }
    });

    // -----------------------------------------------------------------------------
    // Apply To function
    // -----------------------------------------------------------------------------
    $('#apply_all').change(function (e) {
        e.preventDefault();
        const status = $(this)[0].checked;
        $("#emails_wrap input[type=checkbox]").each(function (ind, item) {
            item.checked = status;
        });
    });

    $("#emails_wrap input[type=checkbox]").change(function(){
        const len = $("#emails_wrap input[type=checkbox]").length;
        const len_checked = $("#emails_wrap input[type=checkbox]:checked").length;

        $('#apply_all')[0].checked = len == len_checked;
    });

    // -----------------------------------------------------------------------------
    // End of Apply To function
    // -----------------------------------------------------------------------------

});
var pageAlert = function (type='', duration=3000, content='') {
    let id;
    switch (type) {
        case "primary": {
            id = setInterval(stopAlert, duration);
            $('#alert-wraper').append(
              "<div id=\""+ id +"\" class=\"alert alert-primary\" role=\"alert\">\n" +
              content +
              "</div>"
            );
            break;
        }
        case "secondary": {
            id = setInterval(stopAlert, duration);
            $('#alert-wraper').append(
              "<div id=\""+ id +"\" class=\"alert alert-secondary\" role=\"alert\">\n" +
              content +
              "</div>"
            );
            break;
        }
        case "success": {
            id = setInterval(stopAlert, duration);
            $('#alert-wraper').append(
              "<div id=\""+ id +"\" class=\"alert alert-success\" role=\"alert\">\n" +
              content +
              "</div>"
            );
            break;
        }
        case "danger": {
            id = setInterval(stopAlert, duration);
            $('#alert-wraper').append(
              "<div id=\""+ id +"\" class=\"alert alert-danger\" role=\"alert\">\n" +
              content +
              "</div>"
            );
            break;
        }
        case "warning": {
            id = setInterval(stopAlert, duration);
            $('#alert-wraper').append(
              "<div id=\""+ id +"\" class=\"alert alert-warning\" role=\"alert\">\n" +
              content +
              "</div>"
            );
            break;
        }

    }
    function stopAlert() {
        clearInterval(id);
        $(`#alert-wraper #${id}`).remove();
    }
}