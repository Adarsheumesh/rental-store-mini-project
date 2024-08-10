<?php
$con = mysqli_connect("localhost", "root", "", "project");
if (isset($_POST['userId'])) {
    $id = $_POST['userId'];

    // Retrieve the current status of the customer
    // $status_query = "SELECT `*` FROM `vendors` WHERE `User_id` = $id";
    // $status_result = mysqli_query($con, $status_query);
    // $status = mysqli_fetch_array($status_result)['Status'];

    // Update the customer's status
    if ($status == 1) {
        $disable_query = "UPDATE `vendors` SET `usr_type` = vendor WHERE `User_id` = $id";
        mysqli_query($con, $disable_query);

    } else {
        $enable_query = "UPDATE `vendors` SET `usr_type` = 1 WHERE `User_id` = $id";
        mysqli_query($con, $enable_query);

    }
}