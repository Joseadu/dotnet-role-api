using System;
using System.Collections.Generic;

namespace CustomerAPI.Models
{
    public partial class TblProduct
    {
        public int Code { get; set; }
        public string? Name { get; set; } = "Nombre predeterminado";
        public decimal? Amount { get; set; }
        public string? URL { get; set; } = "Valor predeterminado";
    }
}
