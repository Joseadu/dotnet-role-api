﻿using System;
using System.Collections.Generic;

namespace CustomerAPI.Models
{
    public partial class TblPermission
    {
        public string RoleId { get; set; } = null!;
        public string MenuId { get; set; } = null!;
    }
}
